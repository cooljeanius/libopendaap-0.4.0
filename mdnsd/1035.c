#include "1035.h"
#include <string.h>
#include <stdio.h>

static u_int16_t nettoint16(unsigned char **bufp)
{
    u_int16_t i;
    i = **bufp;
    i <<= 8;
    i |= *(*bufp + 1);
    *bufp += 2;
    return i;
}

static u_int32_t nettoint32(unsigned char **bufp)
{
    u_int32_t l;
    l = **bufp;
    l <<= 8;
    l |= *(*bufp + 1);
    l <<= 8;
    l |= *(*bufp + 2);
    l <<= 8;
    l |= *(*bufp + 3);
    *bufp += 4;
    return l;
}

static void int16tonet(u_int16_t i, unsigned char **bufp)
{
    *(*bufp + 1) = (unsigned char)i;
    i >>= 8;
    **bufp = (unsigned char)i;
    *bufp += 2;    
}

static void int32tonet(u_int32_t l, unsigned char **bufp)
{
    *(*bufp + 3) = (unsigned char)l;
    l >>= 8;
    *(*bufp + 2) = (unsigned char)l;
    l >>= 8;
    *(*bufp + 1) = (unsigned char)l;
    l >>= 8;
    **bufp = (unsigned char)l;
    *bufp += 4;
}

static u_int16_t _ldecomp(unsigned char *ptr)
{
    u_int16_t i;
    i = 0xc0 ^ ptr[0];
    i <<= 8;
    i |= ptr[1];
    if(i >= 4096) i = 4095;
    return i;
}

static void _label(struct message *m, unsigned char **bufp, unsigned char **namep)
{
    unsigned char *label, *name;
    int x;

    // set namep to the end of the block
    *namep = name = m->_packet + m->_len;

    // loop storing label in the block
    for(label = *bufp; *label != 0; name += *label + 1, label += *label + 1)
    {
        // skip past any compression pointers, kick out if end encountered (bad data prolly)
        while(*label & 0xc0)
            if(*(label = m->_buf + _ldecomp(label)) == 0) break;

        // make sure we're not over the limits
        if((name + *label) - *namep > 255 || m->_len + ((name + *label) - *namep) > 4096) return;

        // copy chars for this label
        memcpy(name,label+1,*label);
        name[*label] = '.';
    } 

    // advance buffer
    for(label = *bufp; *label != 0 && !(*label & 0xc0 && label++); label += *label + 1);
    *bufp = label + 1;

    // terminate name and check for cache or cache it
    *name = '\0';
    for(x = 0; x <= 19 && m->_labels[x]; x++)
    {
        if(strcmp(*namep,m->_labels[x])) continue;
        *namep = m->_labels[x];
        return;
    }
    // no cache, so cache it if room
    if(x <= 19 && m->_labels[x] == 0)
        m->_labels[x] = *namep;
    m->_len += (name - *namep) + 1;
}

// internal label matching
static int _lmatch(struct message *m, unsigned char *l1, unsigned char *l2)
{
    int len;

    // always ensure we get called w/o a pointer
    if(*l1 & 0xc0) return _lmatch(m, m->_buf + _ldecomp(l1),l2);
    if(*l2 & 0xc0) return _lmatch(m, l1, m->_buf + _ldecomp(l2));
    
    // same already?
    if(l1 == l2) return 1;
    
    // compare all label characters
    if(*l1 != *l2) return 0;
    for(len = 1; len <= *l1; len++) 
        if(l1[len] != l2[len]) return 0;

    // get new labels
    l1 += *l1 + 1;
    l2 += *l2 + 1;
    
    // at the end, all matched
    if(*l1 == 0 && *l2 == 0) return 1;
    
    // try next labels
    return _lmatch(m,l1,l2);
}

// nasty, convert host into label using compression
static int _host(struct message *m, unsigned char **bufp, unsigned char *name)
{
    unsigned char label[256], *l;
    int len = 0, x = 1, y = 0, last = 0;

    if(name == 0) return 0;

    // make our label
    while(name[y])
    {
        if(name[y] == '.')
        {
            if(!name[y+1]) break;
            label[last] = x - (last + 1);
            last = x;
        }else{
            label[x] = name[y];
        }
        if(x++ == 255) return 0;
        y++;
    }
    label[last] = x - (last + 1);
    if(x == 1) x--; // special case, bad names, but handle correctly
    len = x + 1;
    label[x] = 0; // always terminate w/ a 0

    // double-loop checking each label against all m->_labels for match
    for(x = 0; label[x]; x += label[x] + 1)
    {
        for(y = 0; m->_labels[y]; y++)
            if(_lmatch(m,label+x,m->_labels[y]))
            {
                // matching label, set up pointer
                l = label + x;
                int16tonet(m->_labels[y] - m->_packet, &l);
                label[x] |= 0xc0;
                len = x + 2;
                break;
            }
        if(label[x] & 0xc0) break;
    }

    // copy into buffer, point there now
    memcpy(*bufp,label,len);
    l = *bufp;
    *bufp += len;

    // for each new label, store it's location for future compression
    for(x = 0; l[x]; x += l[x] + 1)
    {
        if(l[x] & 0xc0) break;
        if(m->_label + 1 >= 19) break;
        m->_labels[m->_label++] = l + x;
    }

    return len;
}

static int _rrparse(struct message *m, struct resource *rr, int count, unsigned char **bufp)
{
    int i;
    for(i=0; i < count; i++)
    {
        _label(m, bufp, &(rr[i].name));
        rr[i].type = nettoint16(bufp);
        rr[i].class = nettoint16(bufp);
        rr[i].ttl = nettoint32(bufp);
        rr[i].rdlength = nettoint16(bufp);

        // if not going to overflow, make copy of source rdata
        if(rr[i].rdlength + (*bufp - m->_buf) > MAX_PACKET_LEN || m->_len + rr[i].rdlength > MAX_PACKET_LEN) return 1;
        rr[i].rdata = m->_packet + m->_len;
        m->_len += rr[i].rdlength;
        memcpy(rr[i].rdata,*bufp,rr[i].rdlength);

        // parse commonly known ones
        switch(rr[i].type)
        {
        case 1:
            if(m->_len + 16 > MAX_PACKET_LEN) return 1;
            rr[i].known.a.name = m->_packet + m->_len;
            m->_len += 16;
            sprintf(rr[i].known.a.name,"%d.%d.%d.%d",(*bufp)[0],(*bufp)[1],(*bufp)[2],(*bufp)[3]);
            rr[i].known.a.ip = nettoint32(bufp);
            break;
        case 2:
            _label(m, bufp, &(rr[i].known.ns.name));
            break;
        case 5:
            _label(m, bufp, &(rr[i].known.cname.name));
            break;
        case 12:
            _label(m, bufp, &(rr[i].known.ptr.name));
            break;
        case 33:
            rr[i].known.srv.priority = nettoint16(bufp);
            rr[i].known.srv.weight = nettoint16(bufp);
            rr[i].known.srv.port = nettoint16(bufp);
            _label(m, bufp, &(rr[i].known.srv.name));
            break;            
        default:
            *bufp += rr[i].rdlength;
        }
    }

    return 0;
}

void message_parse(struct message *m, unsigned char *packet)
{
    unsigned char *buf;
    int i;
    
    if(packet == 0 || m == 0) return;

    // keep all our mem in one (aligned) block for easy freeing
    #define my(x,y,t) while(m->_len&7) m->_len++; x = (t)(m->_packet + m->_len); m->_len += y;

    // header stuff bit crap
    m->_buf = buf = packet;
    m->id = nettoint16(&buf);
    if(buf[0] & 0x80) m->header.qr = 1;
    m->header.opcode = (buf[0] & 0x78) >> 3;
    if(buf[0] & 0x04) m->header.aa = 1;
    if(buf[0] & 0x02) m->header.tc = 1;
    if(buf[0] & 0x01) m->header.rd = 1;
    if(buf[1] & 0x80) m->header.ra = 1;
    m->header.z = (buf[1] & 0x70) >> 4;
    m->header.rcode = buf[1] & 0x0F;
    buf += 2;
    m->qdcount = nettoint16(&buf);
    if(m->_len + (sizeof(struct question) * m->qdcount) > MAX_PACKET_LEN - 8) { m->qdcount = 0; return; }
    m->ancount = nettoint16(&buf);
    if(m->_len + (sizeof(struct resource) * m->ancount) > MAX_PACKET_LEN - 8) { m->ancount = 0; return; }
    m->nscount = nettoint16(&buf);
    if(m->_len + (sizeof(struct resource) * m->nscount) > MAX_PACKET_LEN - 8) { m->nscount = 0; return; }
    m->arcount = nettoint16(&buf);
    if(m->_len + (sizeof(struct resource) * m->arcount) > MAX_PACKET_LEN - 8) { m->arcount = 0; return; }

    // process questions
    my(m->qd, sizeof(struct question) * m->qdcount, struct question*);
    for(i=0; i < m->qdcount; i++)
    {
        _label(m, &buf, &(m->qd[i].name));
        m->qd[i].type = nettoint16(&buf);
        m->qd[i].class = nettoint16(&buf);
    }

    // process rrs
    my(m->an, sizeof(struct resource) * m->ancount, struct resource*);
    my(m->ns, sizeof(struct resource) * m->nscount, struct resource*);
    my(m->ar, sizeof(struct resource) * m->arcount, struct resource*);
    if(_rrparse(m,m->an,m->ancount,&buf)) return;
    if(_rrparse(m,m->ns,m->nscount,&buf)) return;
    if(_rrparse(m,m->ar,m->arcount,&buf)) return;
}

void message_qd(struct message *m, unsigned char *name, u_int16_t type, u_int16_t class)
{
    m->qdcount++;
    if(m->_buf == 0) m->_buf = m->_packet + 12; // initialization
    _host(m, &(m->_buf), name);
    int16tonet(type, &(m->_buf));
    int16tonet(class, &(m->_buf));
}

static void _rrappend(struct message *m, unsigned char *name, u_int16_t type, u_int16_t class, u_int32_t ttl)
{
    if(m->_buf == 0) m->_buf = m->_packet + 12; // initialization
    _host(m, &(m->_buf), name);
    int16tonet(type, &(m->_buf));
    int16tonet(class, &(m->_buf));
    int32tonet(ttl, &(m->_buf));
}

void message_an(struct message *m, unsigned char *name, u_int16_t type, u_int16_t class, u_int32_t ttl)
{
    m->ancount++;
    _rrappend(m,name,type,class,ttl);
}

void message_ns(struct message *m, unsigned char *name, u_int16_t type, u_int16_t class, u_int32_t ttl)
{
    m->nscount++;
    _rrappend(m,name,type,class,ttl);
}

void message_ar(struct message *m, unsigned char *name, u_int16_t type, u_int16_t class, u_int32_t ttl)
{
    m->arcount++;
    _rrappend(m,name,type,class,ttl);
}

void message_rdata_long(struct message *m, u_int32_t l)
{
    int16tonet(4, &(m->_buf));
    int32tonet(l, &(m->_buf));
}

void message_rdata_name(struct message *m, unsigned char *name)
{
    unsigned char *mybuf = m->_buf;
    m->_buf += 2;
    int16tonet(_host(m, &(m->_buf), name),&mybuf); // hackish, but cute
}

void message_rdata_srv(struct message *m, u_int16_t priority, u_int16_t weight, u_int16_t port, unsigned char *name)
{
    unsigned char *mybuf = m->_buf;
    m->_buf += 2;
    int16tonet(priority, &(m->_buf));
    int16tonet(weight, &(m->_buf));
    int16tonet(port, &(m->_buf));
    int16tonet(_host(m, &(m->_buf), name) + 6, &mybuf);
}

void message_rdata_raw(struct message *m, unsigned char *rdata, u_int16_t rdlength)
{
    if((m->_buf - m->_packet) + rdlength > 4096) rdlength = 0;
    int16tonet(rdlength, &(m->_buf));
    memcpy(m->_buf,rdata,rdlength);
    m->_buf += rdlength;
}

unsigned char *message_packet(struct message *m)
{
    unsigned char c, *buf = m->_buf;
    m->_buf = m->_packet;
    int16tonet(m->id, &(m->_buf));
    if(m->header.qr) m->_buf[0] |= 0x80;
    if((c = m->header.opcode)) m->_buf[0] |= (c << 3);
    if(m->header.aa) m->_buf[0] |= 0x04;
    if(m->header.tc) m->_buf[0] |= 0x02;
    if(m->header.rd) m->_buf[0] |= 0x01;
    if(m->header.ra) m->_buf[1] |= 0x80;
    if((c = m->header.z)) m->_buf[1] |= (c << 4);
    if(m->header.rcode) m->_buf[1] |= m->header.rcode;
    m->_buf += 2;
    int16tonet(m->qdcount, &(m->_buf));
    int16tonet(m->ancount, &(m->_buf));
    int16tonet(m->nscount, &(m->_buf));
    int16tonet(m->arcount, &(m->_buf));
    m->_buf = buf; // restore, so packet_len works
    return m->_packet;
}

int message_packet_len(struct message *m)
{
    if(m->_buf == 0) return 12;
    return m->_buf - m->_packet;
}