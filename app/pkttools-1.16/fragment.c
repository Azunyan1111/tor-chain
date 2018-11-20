#ifdef __linux__
#define _BSD_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#ifndef USE_NETLIB
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#ifdef __linux__
#include <netinet/ether.h>
#endif
#include <arpa/inet.h>

#include <netinet/ip6.h>
#endif

#include "defines.h"
#ifdef USE_NETLIB
#include <netlib.h>
#endif

#include "pktbuf.h"
#include "fragment.h"
#include "lib.h"

static pktbuf_t packets = NULL;

struct option {
  int linktype;
  int id;

  struct {
    char *hdr;
    int size;
  } iphdr;
  struct {
    char *hdr;
    int size;
  } payload;

  int last;
  int offset;
};

static pktbuf_t split(char *buffer, int size, int linktype,
		      struct timeval *tm, int mtu,
		      char *iphdr, int hdrsize, int paysize, int id)
{
  pktbuf_t pktbuf, pktlist = NULL;
  struct option *opt;
  int s, offset, more;

  pktbuf_init(sizeof(*opt));

  if (mtu < hdrsize + 8)
    error_exit("Lack of MTU size.\n");

  size = minval(paysize, size - hdrsize);
  offset = 0;

  while (size > 0) {
    s = minval(mtu - hdrsize, size);
    more = (s == size) ? 0 : 1;
    if (more) s = (s / 8) * 8;

    if (hdrsize + s > 0xFFFF)
      error_exit("Size is too large.\n");

    pktbuf = pktbuf_create(64);
    pktbuf_set_time(pktbuf, tm);

    opt = pktbuf_get_option(pktbuf);
    opt->linktype = linktype;
    opt->id = id;
    opt->iphdr.hdr = pktbuf_get_header(pktbuf);
    opt->iphdr.size = hdrsize;
    opt->payload.hdr = opt->iphdr.hdr + hdrsize;
    opt->payload.size = s;
    opt->last = more ? 0 : 1;
    opt->offset = offset;

    memcpy(opt->iphdr.hdr, iphdr, hdrsize);
    pktbuf_set_size(pktbuf, hdrsize);

    memcpy(opt->payload.hdr, iphdr + hdrsize + offset, s);
    pktbuf_add_size(pktbuf, s);

    pktbuf_enqueue(&pktlist, pktbuf);

    size -= s;
    offset += s;
  }

  return pktlist;
}

static int fragment(char *buffer, int size, int linktype,
		    struct timeval *tm, int mtu, char *top, int topsize,
		    struct ip *iphdr, int hdrsize, int paysize)
{
  pktbuf_t pktlist, pktbuf;
  struct option *opt;
  int id, more, offset, offset_flag;

  if (mtu == 0)
    mtu = 1500;

  id = ntohs(iphdr->ip_id);
  more = (ntohs(iphdr->ip_off) & IP_MF) ? 1 : 0;
  offset = (ntohs(iphdr->ip_off) & IP_OFFMASK) << 3;

  pktlist = split(buffer, size, linktype, tm, mtu,
		  (char *)iphdr, hdrsize, paysize, id);

  while (1) {
    pktbuf = pktbuf_dequeue(&pktlist);
    if (pktbuf == NULL)
      break;
    opt = pktbuf_get_option(pktbuf);

    pktbuf_add_header(pktbuf, topsize);
    memcpy(pktbuf_get_header(pktbuf), top, topsize);

    iphdr = (struct ip *)opt->iphdr.hdr;

    iphdr->ip_id = htons(opt->id);

    offset_flag  = ((!more && opt->last) ? 0 : IP_MF);
    offset_flag |= (((offset + opt->offset) >> 3) & IP_OFFMASK);
    iphdr->ip_off = htons(offset_flag);

    iphdr->ip_len = htons(opt->iphdr.size + opt->payload.size);

    iphdr->ip_sum = 0;
    iphdr->ip_sum = ~ip_checksum(iphdr, opt->iphdr.size); /* Unneed htons() */

    pktbuf_enqueue(&packets, pktbuf);
  }

  return -1;
}

static int fragment6(char *buffer, int size, int linktype,
		     struct timeval *tm, int mtu, char *top, int topsize,
		     struct ip6_hdr *ip6hdr, int hdrsize, int paysize,
		     int ip6fraghdr_offset, int prev_nexthdr_offset)
{
  pktbuf_t pktlist, pktbuf;
  struct option *opt;
  int id, more, offset, offset_flag;
  struct ip6_frag *ip6fraghdr;
  pkt_uint8 *prev_nexthdr;
  static int default_id = 1;

  if (mtu == 0)
    mtu = 1280;

  if (ip6fraghdr_offset) {
    ip6fraghdr = (struct ip6_frag *)((char *)ip6hdr + ip6fraghdr_offset);
    id = ntohl(ip6fraghdr->ip6f_ident);
    more = (ip6fraghdr->ip6f_offlg & IP6F_MORE_FRAG) ? 1 : 0;
    offset = ntohs(ip6fraghdr->ip6f_offlg & IP6F_OFF_MASK);
  } else {
    mtu -= sizeof(*ip6fraghdr);
    id = default_id++;
    more = 0;
    offset = 0;
  }

  pktlist = split(buffer, size, linktype, tm, mtu,
		  (char *)ip6hdr, hdrsize, paysize, id);

  while (1) {
    pktbuf = pktbuf_dequeue(&pktlist);
    if (pktbuf == NULL)
      break;
    opt = pktbuf_get_option(pktbuf);

    pktbuf_add_header(pktbuf, topsize);
    memcpy(pktbuf_get_header(pktbuf), top, topsize);

    ip6hdr = (struct ip6_hdr *)opt->iphdr.hdr;

    if (ip6fraghdr_offset) {
      ip6fraghdr = (struct ip6_frag *)(opt->iphdr.hdr + ip6fraghdr_offset);
    } else {
      ip6fraghdr = (struct ip6_frag *)(opt->iphdr.hdr + opt->iphdr.size);
      memmove((char *)ip6fraghdr + sizeof(*ip6fraghdr), ip6fraghdr,
	      opt->payload.size);
      memset(ip6fraghdr, 0, sizeof(*ip6fraghdr));
      opt->iphdr.size += sizeof(*ip6fraghdr);
      pktbuf_add_size(pktbuf, sizeof(*ip6fraghdr));

      prev_nexthdr = (pkt_uint8 *)(opt->iphdr.hdr + prev_nexthdr_offset);
      ip6fraghdr->ip6f_nxt = *prev_nexthdr;
      *prev_nexthdr = IPPROTO_FRAGMENT;
    }

    ip6fraghdr->ip6f_ident = htonl(opt->id);

    offset_flag  = ((!more && opt->last) ? 0 : IP6F_MORE_FRAG);
    offset_flag |= htons(offset + opt->offset) & IP6F_OFF_MASK;
    ip6fraghdr->ip6f_offlg = offset_flag; /* Unneed htons() */

    /* Payload Length have IPv6 Extention Headers */
    ip6hdr->ip6_plen =
      htons(opt->iphdr.size - sizeof(struct ip6_hdr) + opt->payload.size);

    pktbuf_enqueue(&packets, pktbuf);
  }

  return -1;
}

static int fragment_ip(char *buffer, int size, int linktype,
		       struct timeval *tm, int mtu, int force,
		       char *top, int topsize)
{
  static char *pktbuf = NULL;
  static int bufsize = 0;
  char *p;
  int s, r = 0;
  struct ip *iphdr;
  int hdrsize, paysize;

  pktbuf = pkt_alloc_buffer(pktbuf, &bufsize, size);

  if (size < sizeof(*iphdr))
    return -1;

  memcpy(pktbuf, buffer, size);
  iphdr = (struct ip *)pktbuf;

  hdrsize = iphdr->ip_hl << 2;
  paysize = ntohs(iphdr->ip_len) - hdrsize;

  p = pktbuf + hdrsize;
  s = size   - hdrsize;

  if ((hdrsize + paysize > mtu) &&
      (force || !(ntohs(iphdr->ip_off) & IP_DF))) {
    r = fragment(pktbuf, size, linktype, tm, mtu,
		 top, topsize, iphdr, hdrsize, paysize);
  }

  if (r < 0)
    return r;

  if (size < hdrsize)
    return -1;

  p += r;
  r = p - pktbuf;

  s = minval(hdrsize + paysize, size) - r;
  if (s > 0) {
    /* If need, attach payload here. */

    p += s;
    r += s;
  }

  return r;
}

static int fragment_ip6(char *buffer, int size, int linktype,
			struct timeval *tm, int mtu, int force,
			char *top, int topsize)
{
  static char *pktbuf = NULL;
  static int bufsize = 0;
  char *p;
  int s, r = 0;
  struct ip6_hdr *ip6hdr;
  int hdrsize, paysize;
  int nexthdr, exthdrsize;
  struct ip6_ext *ip6exthdr;
  struct ip6_rthdr *ip6rthdr;
  struct ip6_frag *ip6fraghdr = NULL;
  pkt_uint8 *prev_nexthdr = NULL;

  pktbuf = pkt_alloc_buffer(pktbuf, &bufsize, size);

  if (size < sizeof(*ip6hdr))
    return -1;

  memcpy(pktbuf, buffer, size);
  ip6hdr = (struct ip6_hdr *)pktbuf;

  hdrsize = sizeof(struct ip6_hdr);
  paysize = ntohs(ip6hdr->ip6_plen);

  p = pktbuf + hdrsize;
  s = size   - hdrsize;

  nexthdr = ip6hdr->ip6_nxt;
  prev_nexthdr = &ip6hdr->ip6_nxt;

  while (1) {
    exthdrsize = 0;
    switch (nexthdr) {
    case IPPROTO_HOPOPTS:
    case IPPROTO_DSTOPTS:
      if (s < sizeof(*ip6exthdr))
	return -1;
      ip6exthdr = (struct ip6_ext *)p;
      nexthdr = ip6exthdr->ip6e_nxt;
      exthdrsize = (ip6exthdr->ip6e_len + 1) << 3;
      prev_nexthdr = &ip6exthdr->ip6e_nxt;
      break;
    case IPPROTO_ROUTING:
      if (s < sizeof(*ip6rthdr))
	return -1;
      ip6rthdr = (struct ip6_rthdr *)p;
      nexthdr = ip6rthdr->ip6r_nxt;
      exthdrsize = (ip6rthdr->ip6r_len + 1) << 3;
      prev_nexthdr = &ip6rthdr->ip6r_nxt;
      break;
    case IPPROTO_FRAGMENT:
      if (s < sizeof(*ip6fraghdr))
	return -1;
      ip6fraghdr = (struct ip6_frag *)p;
      nexthdr = ip6fraghdr->ip6f_nxt;
      exthdrsize = sizeof(*ip6fraghdr);
      break;
    case IPPROTO_NONE:
    default:
      break;
    }
    if (exthdrsize == 0)
      break;
    if (s < exthdrsize)
      return -1;
    p       += exthdrsize;
    s       -= exthdrsize;
    hdrsize += exthdrsize;
    paysize -= exthdrsize;
  }

  if (hdrsize + paysize > mtu) {
    r = fragment6(pktbuf, size, linktype, tm, mtu,
		  top, topsize, ip6hdr, hdrsize, paysize,
		  (ip6fraghdr ? ((char *)ip6fraghdr - (char *)ip6hdr) : 0),
		  (char *)prev_nexthdr - (char *)ip6hdr);
  }

  if (r < 0)
    return r;

  p += r;
  r = p - pktbuf;

  s = minval(hdrsize + paysize, size) - r;
  if (s > 0) {
    /* If need, attach payload here. */

    p += s;
    r += s;
  }

  return r;
}

static int fragment_loopback(char *buffer, int size, int linktype,
			     struct timeval *tm, int mtu, int force)
{
  char *p;
  int s, r = 0;
  pkt_uint32 family;

  if (size < sizeof(family))
    return -1;
  memcpy(&family, buffer, sizeof(family)); /* Unneed ntohl() */

  p = buffer + sizeof(family);
  s = size   - sizeof(family);

  switch (family) {
  case AF_INET:
    r = fragment_ip( p, s, linktype, tm, mtu, force, buffer, p - buffer);
    break;
  case AF_INET6:
    r = fragment_ip6(p, s, linktype, tm, mtu, force, buffer, p - buffer);
    break;
  default:
    break;
  }

  if (r < 0)
    return r;

  p += r;
  r = p - buffer;

  s = size - r;
  if (s > 0) {
    /* If need, attach payload here. */

    p += s;
    r += s;
  }

  return r;
}

static int fragment_ethernet(char *buffer, int size, int linktype,
			     struct timeval *tm, int mtu, int force)
{
  char *p;
  int s, r = 0;
  struct ether_header ehdr;
  struct {
    pkt_uint16 tag;
    pkt_uint16 proto;
  } vlantag;
  int type;

  if (size < ETHER_HDR_LEN)
    return -1;
  memcpy(&ehdr, buffer, ETHER_HDR_LEN);

  type = ntohs(ehdr.ether_type);
  p = buffer + ETHER_HDR_LEN;
  s = size   - ETHER_HDR_LEN;

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100
#endif
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86DD
#endif

  while (type == ETHERTYPE_VLAN) {
    if (s < sizeof(vlantag))
      return -1;
    memcpy(&vlantag, p, sizeof(vlantag));
    type = ntohs(vlantag.proto);
    p += sizeof(vlantag);
    s -= sizeof(vlantag);
  }

  ehdr.ether_type = htons(type);

  switch (type) {
  case ETHERTYPE_IP:
    r = fragment_ip( p, s, linktype, tm, mtu, force, buffer, p - buffer);
    break;
  case ETHERTYPE_IPV6:
    r = fragment_ip6(p, s, linktype, tm, mtu, force, buffer, p - buffer);
    break;
  default:
    break;
  }

  if (r < 0)
    return r;

  p += r;
  r = p - buffer;

  s = size - r;
  if (s > 0) {
    /* If need, attach payload here. */

    p += s;
    r += s;
  }

  return r;
}

int pkt_fragment(char *buffer, int size, int linktype, int origsize,
		 struct timeval *tm, int mtu, int force)
{
  char *p;
  int s, r = 0;

  p = buffer;
  s = size;

  switch (linktype) {
  case DLT_NULL:
    r = fragment_loopback(p, s, linktype, tm, mtu, force);
    break;
  case DLT_EN10MB:
    r = fragment_ethernet(p, s, linktype, tm, mtu, force);
    break;
  default:
    break;
  }

  if (r < 0)
    return r;

  p += r;
  r = p - buffer;

  s = size - r;
  if (s > 0) {
    /* If need, attach payload here. */

    p += s;
    r += s;
  }

  return r;
}

int pkt_fragment_dequeue(char *buffer, int size, int *linktypep,
			 int *origsizep, struct timeval *tm)
{
  pktbuf_t pktbuf;
  struct option *opt;
  int s;

  pktbuf = pktbuf_dequeue(&packets);
  if (pktbuf == NULL)
    return 0;

  s = pktbuf_get_size(pktbuf);
  if (size < s)
    error_exit("Out of buffer.\n");
  memcpy(buffer, pktbuf_get_header(pktbuf), s);
  if (linktypep) {
    opt = pktbuf_get_option(pktbuf);
    *linktypep = opt->linktype;
  }
  if (origsizep) *origsizep = s;
  if (tm) {
    tm->tv_sec  = pktbuf_get_time(pktbuf)->tv_sec;
    tm->tv_usec = pktbuf_get_time(pktbuf)->tv_usec;
  }
  pktbuf_destroy(pktbuf);
  return s;
}
