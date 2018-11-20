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
#include "defragment.h"
#include "lib.h"

static pktbuf_t pktlist_ip = NULL;
static pktbuf_t pktlist_ip6 = NULL;
static pktbuf_t packets = NULL;

struct option {
  int linktype;
  int id;

  struct {
    char *hdr;
    int size;
  } top;
  struct {
    char *hdr;
    int size;
  } iphdr;
  struct {
    char *hdr;
    int size;
  } payload;

  union {
    struct {
      int last;
      int complete;
      pktbuf_t waiting;
    } restruct;
    struct {
      int more;
      int offset;
    } waiting;
  } u;
};

static int restructure_waiting(pktbuf_t restruct)
{
  pktbuf_t pktbuf, halfway;
  struct option *ropt, *opt;
  int finished = 0, size;

  ropt = pktbuf_get_option(restruct);

  while (!finished) {
    halfway = NULL;
    finished = 1;
    while (1) {
      pktbuf = pktbuf_dequeue(&ropt->u.restruct.waiting);
      if (pktbuf == NULL)
	break;
      opt = pktbuf_get_option(pktbuf);
      if (opt->u.waiting.offset > ropt->payload.size) {
	pktbuf_enqueue(&halfway, pktbuf);
	continue;
      }

      finished = 0;
      if (opt->u.waiting.offset == 0) {
	pktbuf_set_time(restruct, pktbuf_get_time(pktbuf));

	ropt->linktype = opt->linktype;
	ropt->iphdr.hdr = pktbuf_get_header(restruct);
	ropt->iphdr.size = opt->iphdr.size;
	ropt->top.hdr = pktbuf_add_header(restruct, opt->top.size);
	ropt->top.size = opt->top.size;
	ropt->payload.hdr = ropt->iphdr.hdr + opt->iphdr.size;
	ropt->payload.size = 0;

	memcpy(ropt->top.hdr, opt->top.hdr, ropt->top.size);
	memcpy(ropt->iphdr.hdr, opt->iphdr.hdr, ropt->iphdr.size);
      }

      if (opt->u.waiting.offset + opt->payload.size > 0xFFFF)
	error_exit("Size is too large.\n");

      size = pktbuf_get_size(pktbuf) - (opt->top.size + opt->iphdr.size);
      memcpy(ropt->payload.hdr + opt->u.waiting.offset, opt->payload.hdr,
	     minval(opt->payload.size, size));

      ropt->payload.size = maxval(ropt->payload.size,
				  opt->u.waiting.offset + opt->payload.size);

      size = ropt->top.size + ropt->iphdr.size + ropt->payload.size;
      pktbuf_set_size(restruct, size);

      if (!opt->u.waiting.more)
	ropt->u.restruct.last = 1;
      if (ropt->u.restruct.last && (ropt->u.restruct.waiting == NULL))
	ropt->u.restruct.complete = 1;

      pktbuf_destroy(pktbuf);
    }

    ropt->u.restruct.waiting = halfway;
  }

  return 0;
}

static pktbuf_t restructure(char *buffer, int size, int linktype,
			    struct timeval *tm,
			    pktbuf_t *pktlist, char *top, int topsize,
			    char *iphdr, int hdrsize, int paysize,
			    int id, int more, int offset)
{
  pktbuf_t pktbuf, halfway = NULL, restruct;
  struct option *ropt, *opt;

  pktbuf_init(sizeof(*opt));

  while (1) {
    restruct = pktbuf_dequeue(pktlist);
    if (restruct == NULL)
      break;
    ropt = pktbuf_get_option(restruct);
    if (ropt->id == id)
      break;
    pktbuf_enqueue(&halfway, restruct);
  }

  if (restruct == NULL) {
    restruct = pktbuf_create(64);
    ropt = pktbuf_get_option(restruct);
    ropt->id = id;
    ropt->payload.size = 0;

    ropt->u.restruct.last = 0;
    ropt->u.restruct.complete = 0;
    ropt->u.restruct.waiting = NULL;
  }

  pktbuf = pktbuf_create(64);
  pktbuf_set_time(pktbuf, tm);
  pktbuf_set_size(pktbuf, size);
  opt = pktbuf_get_option(pktbuf);
  opt->linktype = linktype;
  opt->id = id;

  opt->iphdr.hdr = pktbuf_get_header(pktbuf);
  opt->iphdr.size = hdrsize;
  opt->top.hdr = pktbuf_add_header(pktbuf, topsize);
  opt->top.size = topsize;
  opt->payload.hdr = opt->iphdr.hdr + hdrsize;
  opt->payload.size = paysize;

  opt->u.waiting.more = more;
  opt->u.waiting.offset = offset;

  memcpy(opt->top.hdr, top, topsize);
  memcpy(opt->iphdr.hdr, iphdr, hdrsize);
  memcpy(opt->payload.hdr, iphdr + hdrsize, minval(paysize, size - hdrsize));

  pktbuf_enqueue(&ropt->u.restruct.waiting, pktbuf);

  restructure_waiting(restruct);

  if (ropt->u.restruct.complete) {
    pktbuf_enqueue(&packets, restruct);
  } else {
    pktbuf_enqueue(&halfway, restruct);
  }

  *pktlist = pktbuf_enqueue(&halfway, *pktlist);

  return restruct;
}

static int defragment(char *buffer, int size, int linktype,
		      struct timeval *tm, char *top, int topsize,
		      struct ip *iphdr, int hdrsize, int paysize,
		      int id, int more, int offset)
{
  pktbuf_t pktbuf;
  struct option *opt;

  pktbuf = restructure(buffer, size, linktype, tm, &pktlist_ip, top, topsize,
		       (char *)iphdr, hdrsize, paysize, id, more, offset);
  opt = pktbuf_get_option(pktbuf);

  if (opt->u.restruct.complete) {
    iphdr = (struct ip *)opt->iphdr.hdr;

    size = pktbuf_get_size(pktbuf) - opt->top.size;
    if (size > 0xFFFF)
      error_exit("Size is too large.\n");

    iphdr->ip_off = 0;
    iphdr->ip_len = htons(size);
    iphdr->ip_sum = 0;
    iphdr->ip_sum = ~ip_checksum(iphdr, opt->iphdr.size); /* Unneed htons() */
  }

  return -1;
}

static int defragment6(char *buffer, int size, int linktype,
		       struct timeval *tm, char *top, int topsize,
		       struct ip6_hdr *ip6hdr, int hdrsize, int paysize,
		       int id, int more, int offset,
		       struct ip6_frag *ip6fraghdr, pkt_uint8 *prev_nexthdr)
{
  pktbuf_t pktbuf;
  struct option *opt;

  *prev_nexthdr = ip6fraghdr->ip6f_nxt;
  memmove(ip6fraghdr, (char *)ip6fraghdr + sizeof(*ip6fraghdr),
	  hdrsize + paysize
	  - (((char *)ip6fraghdr + sizeof(*ip6fraghdr)) - (char *)ip6hdr));
  hdrsize -= sizeof(*ip6fraghdr);
  size -= sizeof(*ip6fraghdr);

  pktbuf = restructure(buffer, size, linktype, tm, &pktlist_ip6, top, topsize,
		       (char *)ip6hdr, hdrsize, paysize, id, more, offset);
  opt = pktbuf_get_option(pktbuf);

  if (opt->u.restruct.complete) {
    ip6hdr = (struct ip6_hdr *)opt->iphdr.hdr;

    /* Payload Length have IPv6 Extention Headers */
    size = pktbuf_get_size(pktbuf) - (opt->top.size + sizeof(struct ip6_hdr));
    if (size > 0xFFFF)
      error_exit("Size is too large.\n");

    ip6hdr->ip6_plen = htons(size);
  }

  return -1;
}

static int defragment_ip(char *buffer, int size, int linktype,
			 struct timeval *tm, char *top, int topsize)
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

  if ((ntohs(iphdr->ip_off) & (IP_MF|IP_OFFMASK)) != 0) {
    r = defragment(pktbuf, size, linktype, tm,
		   top, topsize, iphdr, hdrsize, paysize,
		   ntohs(iphdr->ip_id), (ntohs(iphdr->ip_off) & IP_MF) ? 1 : 0,
		   ((ntohs(iphdr->ip_off) & IP_OFFMASK) << 3));
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

static int defragment_ip6(char *buffer, int size, int linktype,
			  struct timeval *tm, char *top, int topsize)
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

  if (ip6fraghdr != NULL) {
    r = defragment6(pktbuf, size, linktype, tm,
		    top, topsize, ip6hdr, hdrsize, paysize,
		    ntohl(ip6fraghdr->ip6f_ident),
		    (ip6fraghdr->ip6f_offlg & IP6F_MORE_FRAG) ? 1 : 0,
		    ntohs(ip6fraghdr->ip6f_offlg & IP6F_OFF_MASK),
		    ip6fraghdr, prev_nexthdr);
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

static int defragment_loopback(char *buffer, int size, int linktype,
			       struct timeval *tm)
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
    r = defragment_ip( p, s, linktype, tm, buffer, p - buffer);
    break;
  case AF_INET6:
    r = defragment_ip6(p, s, linktype, tm, buffer, p - buffer);
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

static int defragment_ethernet(char *buffer, int size, int linktype,
			       struct timeval *tm)
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
    r = defragment_ip( p, s, linktype, tm, buffer, p - buffer);
    break;
  case ETHERTYPE_IPV6:
    r = defragment_ip6(p, s, linktype, tm, buffer, p - buffer);
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

int pkt_defragment(char *buffer, int size, int linktype, int origsize,
		   struct timeval *tm)
{
  char *p;
  int s, r = 0;

  p = buffer;
  s = size;

  switch (linktype) {
  case DLT_NULL:   r = defragment_loopback(p, s, linktype, tm); break;
  case DLT_EN10MB: r = defragment_ethernet(p, s, linktype, tm); break;
  default: break;
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

int pkt_defragment_dequeue(char *buffer, int size, int *linktypep,
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
