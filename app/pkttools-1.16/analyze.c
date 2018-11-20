#ifdef __linux__
#define _BSD_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#ifndef USE_NETLIB
#include <sys/socket.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#ifdef __linux__
#include <netinet/ether.h>
#endif
#include <arpa/inet.h>

#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#endif

#include "defines.h"
#ifdef USE_NETLIB
#include <netlib.h>
#endif

#include "analyze.h"
#include "lib.h"

struct print_params {
  int low_layer;
  int high_layer;
  int layer;
  int level;
};
typedef struct print_params *params_t;

static int is_valid(params_t pp)
{
  if (pp->layer && pp->low_layer  && (pp->layer < pp->low_layer )) return 0;
  if (pp->layer && pp->high_layer && (pp->layer > pp->high_layer)) return 0;
  return 1;
}

static int is_print(params_t pp, int level)
{
  if (!is_valid(pp)) return 0;
  if (level && pp->level && (level > pp->level)) return 0;
  return 1;
}

static int is_printeq(params_t pp, int level)
{
  if (!is_valid(pp)) return 0;
  if (!level || !pp->level || level != pp->level) return 0;
  return 1;
}

#define PRINT(fp, p, level, args...) \
	do { \
		if (is_print(p, (level))) { \
			fprintf((fp), args); \
		} \
	} while (0)
#define PRINTEQ(fp, p, level, args...) \
	do { \
		if (is_printeq(p, (level))) { \
			fprintf((fp), args); \
		} \
	} while (0)

struct pseudo_header {
  in_addr_t saddr;
  in_addr_t daddr;
  pkt_uint8 zero;
  pkt_uint8 protocol;
  pkt_uint16 len;
};

struct pseudo6_header {
  struct in6_addr saddr;
  struct in6_addr daddr;
  pkt_uint32 len;
  pkt_uint8 zero[3];
  pkt_uint8 nexthdr;
};

#define COLUMN 8

static int print_payload(FILE *fp, char *buffer, int size, params_t pp,
			 char *name)
{
  char text[COLUMN * 2 + 1];
  char *textp = NULL;
  unsigned char c;
  int i, n = 0, align_size;

  if (!is_print(pp, 4))
    return 0;

  align_size = ((size + COLUMN - 1) / COLUMN) * COLUMN;
  for (i = 0; i < align_size; i++) {
    if ((i % COLUMN) == 0) {
      n = 0;
      textp = text;
      if (i == 0) {
	fprintf(fp, "DATA\t%s\t%s:", name, (strlen(name) < 8) ? "\t" : "");
      } else {
	fprintf(fp, "\t\t\t:");
      }
    }

    if ((n % 4) == 0)
      fprintf(fp, " ");

    if (!is_print(pp, 5)) {
      if ((i / COLUMN) == 4) {
	fprintf(fp, "...\n");
	break;
      }
    }

    if (i < size) {
      c = buffer[i];
      fprintf(fp, "%02X ", c);
    } else {
      c = ' ';
      fprintf(fp, "   ");
    }

    if ((n % 4) == 0) *(textp++) = ' ';
    *(textp++) = isprint(c) ? c : '.';
    *textp = '\0';

    if ((i % COLUMN) == (COLUMN - 1))
      fprintf(fp, ":%s\n", text);

    n++;
  }

  return 0;
}

static int analyze_arp(FILE *fp, char *buffer, int size, params_t pp)
{
  struct arphdr arphdr;
  char *p, *smac, *tmac, *sip, *tip;
  struct arpdata {
    union {
      char *octet;
      struct ether_addr *addr;
    } sender_macaddr;
    union {
      char *octet;
      struct ether_addr *addr;
    } target_macaddr;
    struct in_addr sender_ipaddr;
    struct in_addr target_ipaddr;
  } arpdata;

  if (size < sizeof(arphdr))
    return -1;
  memcpy(&arphdr, buffer, sizeof(arphdr));

  PRINT(fp, pp, 1, "ARP");
  PRINTEQ(fp, pp, 1, ":");
  PRINT(fp, pp, 2, "\toperation\t: %d", ntohs(arphdr.ar_op));
  PRINTEQ(fp, pp, 2, " (");
  PRINT(fp, pp, 3, "\n");
  PRINT(fp, pp, 3, "\thrd/prt (size)\t: %d / 0x%04x (%d / %d)\n",
	ntohs(arphdr.ar_hrd), ntohs(arphdr.ar_pro),
	arphdr.ar_hln, arphdr.ar_pln);

  if ((ntohs(arphdr.ar_hrd) != ARPHRD_ETHER) ||
      (ntohs(arphdr.ar_pro) != ETHERTYPE_IP) ||
      (arphdr.ar_hln != ETHER_ADDR_LEN) ||
      (arphdr.ar_pln != sizeof(in_addr_t)))
    return -1;

  if (size < sizeof(struct arphdr) + arphdr.ar_hln * 2 + arphdr.ar_pln * 2)
    return -1;

  p = buffer + sizeof(struct arphdr);
  smac = p; p += arphdr.ar_hln;
  sip  = p; p += arphdr.ar_pln;
  tmac = p; p += arphdr.ar_hln;
  tip  = p; p += arphdr.ar_pln;

  arpdata.sender_macaddr.octet = smac;
  arpdata.target_macaddr.octet = tmac;
  memcpy(&arpdata.sender_ipaddr.s_addr, sip, sizeof(in_addr_t));
  memcpy(&arpdata.target_ipaddr.s_addr, tip, sizeof(in_addr_t));

  PRINT(fp, pp, 3, "\tsender MAC/IP\t: %s    \t/ ",
	ether_ntoa(arpdata.sender_macaddr.addr));
  PRINT(fp, pp, 2, "%s", inet_ntoa(arpdata.sender_ipaddr));
  PRINT(fp, pp, 3, "\n");

  PRINTEQ(fp, pp, 2, " -> ");

  PRINT(fp, pp, 3, "\ttarget MAC/IP\t: %s    \t/ ",
	ether_ntoa(arpdata.target_macaddr.addr));
  PRINT(fp, pp, 2, "%s", inet_ntoa(arpdata.target_ipaddr));
  PRINTEQ(fp, pp, 2, ")");
  PRINT(fp, pp, 2, "\n");

  size = p - buffer;

  return size;
}

static int analyze_icmp(FILE *fp, char *buffer, int size, params_t pp,
			int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct icmp *icmphdr;
  int chksum, origsum;

  if (size < sizeof(*icmphdr))
    return -1;
  icmphdr = (struct icmp *)buffer;

  PRINT(fp, pp, 1, "ICMP");
  PRINTEQ(fp, pp, 1, ":");
  PRINT(fp, pp, 3, "\ttotal size\t: %d bytes\n", total_size);
  PRINT(fp, pp, 2, "\ttype/code\t: %d / %d\n",
	icmphdr->icmp_type, icmphdr->icmp_code);
  PRINT(fp, pp, 3, "\tchecksum\t: 0x%04x", ntohs(icmphdr->icmp_cksum));

  if (size < total_size) {
    PRINT(fp, pp, 3, " (Uncheck)\n");
  } else {
    origsum = icmphdr->icmp_cksum;
    /* This is compatible with FreeBSD */
    icmphdr->icmp_cksum = 0;
    chksum = ~ip_checksum(icmphdr, total_size) & 0xffff;
    if (origsum == chksum) {
      PRINT(fp, pp, 3, " (Valid)\n");
    } else {
      PRINT(fp, pp, 3, " (0x%04x)\n", ntohs(chksum));
    }
    icmphdr->icmp_cksum = origsum;
  }

  s = sizeof(*icmphdr);
  p += s;
  r += s;

  s = minval(total_size, size) - r;
  if (s > 0) {
    print_payload(fp, p, s, pp, "ICMP");
    p += s;
    r += s;
  }

  return r;
}

static int analyze_igmp(FILE *fp, char *buffer, int size, params_t pp,
			int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct igmp *igmphdr;
  int chksum, origsum;

  if (size < sizeof(*igmphdr))
    return -1;
  igmphdr = (struct igmp *)buffer;

  PRINT(fp, pp, 1, "IGMP");
  PRINTEQ(fp, pp, 1, ":");
  PRINT(fp, pp, 3, "\ttotal size\t: %d bytes\n", total_size);
  PRINT(fp, pp, 2, "\ttype/code\t: %d / %d\n",
	igmphdr->igmp_type, igmphdr->igmp_code);
  PRINT(fp, pp, 3, "\tchecksum\t: 0x%04x", ntohs(igmphdr->igmp_cksum));

  if (size < total_size) {
    PRINT(fp, pp, 3, " (Uncheck)\n");
  } else {
    origsum = igmphdr->igmp_cksum;
    /* This is compatible with FreeBSD */
    igmphdr->igmp_cksum = 0;
    chksum = ~ip_checksum(igmphdr, sizeof(struct igmp)) & 0xffff;
    if (origsum == chksum) {
      PRINT(fp, pp, 3, " (Valid)\n");
    } else {
      PRINT(fp, pp, 3, " (0x%04x)\n", ntohs(chksum));
    }
    igmphdr->igmp_cksum = origsum;
  }

  PRINT(fp, pp, 3, "\tgroup\t\t: %s\n", inet_ntoa(igmphdr->igmp_group));

  s = sizeof(*igmphdr);
  p += s;
  r += s;

  s = minval(total_size, size) - r;
  if (s > 0) {
    print_payload(fp, p, s, pp, "IGMP");
    p += s;
    r += s;
  }

  return r;
}

static int analyze_tcp(FILE *fp, char *buffer, int size, params_t pp,
		       int total_size, int pchksum)
{
  char *p = buffer;
  int s, r = 0;
  struct tcphdr *tcphdr;
  int chksum, origsum;

  if (size < sizeof(*tcphdr))
    return -1;
  tcphdr = (struct tcphdr *)buffer;

  PRINT(fp, pp, 1, "TCP");
  PRINTEQ(fp, pp, 1, ":");
  PRINT(fp, pp, 3, "\ttotal size\t: %d bytes\n", total_size);
  PRINT(fp, pp, 2, "\tsrc/dst port\t: %d / %d\n",
	ntohs(tcphdr->th_sport), ntohs(tcphdr->th_dport));
  PRINT(fp, pp, 3, "\tseq/ack number\t: %u / %u\n",
	ntohl(tcphdr->th_seq), ntohl(tcphdr->th_ack));
  PRINT(fp, pp, 3, "\toffset/window\t: %d / %d\n",
	(tcphdr->th_off << 2), ntohs(tcphdr->th_win));
  PRINT(fp, pp, 3, "\tchecksum/flags\t: 0x%04x", ntohs(tcphdr->th_sum));

  if (size < total_size) {
    PRINT(fp, pp, 3, " (Uncheck)");
  } else {
    origsum = tcphdr->th_sum;
    /* This is compatible with FreeBSD */
    tcphdr->th_sum = pchksum; /* Unneed htons() */
    chksum = ~ip_checksum(tcphdr, total_size) & 0xffff;
    if (origsum == chksum) {
      PRINT(fp, pp, 3, " (Valid)");
    } else {
      PRINT(fp, pp, 3, " (0x%04x)", ntohs(chksum));
    }
    tcphdr->th_sum = origsum;
  }

  PRINT(fp, pp, 3, " / 0x%02x ( ", tcphdr->th_flags);
  if (tcphdr->th_flags & TH_FIN ) PRINT(fp, pp, 3, "FIN ");
  if (tcphdr->th_flags & TH_SYN ) PRINT(fp, pp, 3, "SYN ");
  if (tcphdr->th_flags & TH_RST ) PRINT(fp, pp, 3, "RST ");
  if (tcphdr->th_flags & TH_PUSH) PRINT(fp, pp, 3, "PSH ");
  if (tcphdr->th_flags & TH_ACK ) PRINT(fp, pp, 3, "ACK ");
  if (tcphdr->th_flags & TH_URG ) PRINT(fp, pp, 3, "URG ");
  PRINT(fp, pp, 3, ")\n");

  s = sizeof(*tcphdr);
  p += s;
  r += s;

  s = minval(total_size, size) - r;
  if (s > 0) {
    print_payload(fp, p, s, pp, "TCP");
    p += s;
    r += s;
  }

  return r;
}

static int analyze_udp(FILE *fp, char *buffer, int size, params_t pp,
		       int total_size, int pchksum)
{
  char *p = buffer;
  int s, r = 0;
  struct udphdr *udphdr;
  int chksum, origsum;

  if (size < sizeof(*udphdr))
    return -1;
  udphdr = (struct udphdr *)buffer;

  PRINT(fp, pp, 1, "UDP");
  PRINTEQ(fp, pp, 1, ":");
  PRINT(fp, pp, 3, "\ttotal size\t: %d bytes\n", total_size);
  PRINT(fp, pp, 2, "\tsrc/dst port\t: %d / %d\n",
	ntohs(udphdr->uh_sport), ntohs(udphdr->uh_dport));
  PRINT(fp, pp, 3, "\tlength/checksum\t: %d / 0x%04x",
	ntohs(udphdr->uh_ulen), ntohs(udphdr->uh_sum));

  if (size < total_size) {
    PRINT(fp, pp, 3, " (Uncheck)\n");
  } else {
    origsum = udphdr->uh_sum;
    /* This is compatible with FreeBSD */
    udphdr->uh_sum = pchksum; /* Unneed htons() */
    chksum = ~ip_checksum(udphdr, total_size) & 0xffff;
    if (origsum == chksum) {
      PRINT(fp, pp, 3, " (Valid)\n");
    } else {
      PRINT(fp, pp, 3, " (0x%04x)\n", ntohs(chksum));
    }
    udphdr->uh_sum = origsum;
  }

  s = sizeof(*udphdr);
  p += s;
  r += s;

  s = minval(total_size, size) - r;
  if (s > 0) {
    print_payload(fp, p, s, pp, "UDP");
    p += s;
    r += s;
  }

  return r;
}

static int analyze_ip(FILE *fp, char *buffer, int size, params_t pp)
{
  static char *pktbuf = NULL;
  static int bufsize = 0;
  char *p;
  int s, r = 0;
  struct ip *iphdr;
  int hdrsize, paysize;
  struct pseudo_header phdr;
  int pchksum, chksum, origsum;

  pktbuf = pkt_alloc_buffer(pktbuf, &bufsize, size);

  if (size < sizeof(*iphdr))
    return -1;

  memcpy(pktbuf, buffer, size);
  iphdr = (struct ip *)pktbuf;

  hdrsize = iphdr->ip_hl << 2;
  paysize = ntohs(iphdr->ip_len) - hdrsize;

  PRINT(fp, pp, 1, "IP");
  PRINTEQ(fp, pp, 1, ":");
  PRINT(fp, pp, 3, "\thead/total size\t: %d / %d bytes\n",
	hdrsize, ntohs(iphdr->ip_len));
  PRINT(fp, pp, 3, "\tID/fragment\t: 0x%04x / 0x%04x\n",
	ntohs(iphdr->ip_id), ntohs(iphdr->ip_off));
  PRINT(fp, pp, 3, "\tTTL/protocol\t: %d / %d\n", iphdr->ip_ttl, iphdr->ip_p);
  PRINT(fp, pp, 3, "\tchecksum\t: 0x%04x", ntohs(iphdr->ip_sum));

  if (size < hdrsize) {
    PRINT(fp, pp, 3, " (Uncheck)\n");
  } else {
    origsum = iphdr->ip_sum;
    /* This is compatible with FreeBSD */
    iphdr->ip_sum = 0;
    chksum = ~ip_checksum(iphdr, hdrsize) & 0xffff;
    if (origsum == chksum) {
      PRINT(fp, pp, 3, " (Valid)\n");
    } else {
      PRINT(fp, pp, 3, " (0x%04x)\n", ntohs(chksum));
    }
    iphdr->ip_sum = origsum;
  }

  PRINT(fp, pp, 2, "\tsrc/dst addr\t: %s / ", inet_ntoa(iphdr->ip_src));
  PRINT(fp, pp, 2, "%s\n", inet_ntoa(iphdr->ip_dst));

  p = pktbuf + hdrsize;
  s = size   - hdrsize;

  memset(&phdr, 0, sizeof(phdr));
  phdr.saddr = iphdr->ip_src.s_addr;
  phdr.daddr = iphdr->ip_dst.s_addr;
  phdr.protocol = iphdr->ip_p;
  phdr.len = htons(paysize);
  pchksum = ip_checksum(&phdr, sizeof(phdr));

  pp->layer++;
  if ((ntohs(iphdr->ip_off) & (IP_MF|IP_OFFMASK)) == 0) {
    switch (iphdr->ip_p) {
    case IPPROTO_ICMP: r = analyze_icmp(fp, p, s, pp, paysize); break;
    case IPPROTO_IGMP: r = analyze_igmp(fp, p, s, pp, paysize); break;
    case IPPROTO_TCP:  r = analyze_tcp( fp, p, s, pp, paysize, pchksum); break;
    case IPPROTO_UDP:  r = analyze_udp( fp, p, s, pp, paysize, pchksum); break;
    default: break;
    }
  }
  pp->layer--;

  if (r < 0)
    return r;

  p += r;
  r = p - pktbuf;

  s = minval(hdrsize + paysize, size) - r;
  if (s > 0) {
    print_payload(fp, p, s, pp, "IP");
    p += s;
    r += s;
  }

  return r;
}

static int analyze_icmp6(FILE *fp, char *buffer, int size, params_t pp,
			 int total_size, int pchksum)
{
  char *p = buffer;
  int s, r = 0;
  struct icmp6_hdr *icmp6hdr;
  int chksum, origsum;

  if (size < sizeof(*icmp6hdr))
    return -1;
  icmp6hdr = (struct icmp6_hdr *)buffer;

  PRINT(fp, pp, 1, "ICMPv6");
  PRINTEQ(fp, pp, 1, ":");
  PRINT(fp, pp, 3, "\ttotal size\t: %d bytes\n", total_size);
  PRINT(fp, pp, 2, "\ttype/code\t: %d / %d\n",
	icmp6hdr->icmp6_type, icmp6hdr->icmp6_code);
  PRINT(fp, pp, 3, "\tchecksum\t: 0x%04x", ntohs(icmp6hdr->icmp6_cksum));

  if (size < total_size) {
    PRINT(fp, pp, 3, " (Uncheck)\n");
  } else {
    origsum = icmp6hdr->icmp6_cksum;
    /* This is compatible with FreeBSD */
    icmp6hdr->icmp6_cksum = pchksum; /* Unneed htons() */
    chksum = ~ip_checksum(icmp6hdr, total_size) & 0xffff;
    if (origsum == chksum) {
      PRINT(fp, pp, 3, " (Valid)\n");
    } else {
      PRINT(fp, pp, 3, " (0x%04x)\n", ntohs(chksum));
    }
    icmp6hdr->icmp6_cksum = origsum;
  }

  s = sizeof(*icmp6hdr);
  p += s;
  r += s;

  s = minval(total_size, size) - r;
  if (s > 0) {
    print_payload(fp, p, s, pp, "ICMPv6");
    p += s;
    r += s;
  }

  return r;
}

static int analyze_ip6(FILE *fp, char *buffer, int size, params_t pp)
{
  static char *pktbuf = NULL;
  static int bufsize = 0;
  char *p;
  int s, r = 0;
  struct ip6_hdr *ip6hdr;
  int hdrsize, paysize;
  int nexthdr, next_nexthdr = 0, exthdrsize;
  struct ip6_ext *ip6exthdr = NULL;
  struct ip6_rthdr *ip6rthdr = NULL;
  struct ip6_frag *ip6fraghdr = NULL;
  struct pseudo6_header phdr;
  int pchksum;
  char addrs[INET6_ADDRSTRLEN];

  pktbuf = pkt_alloc_buffer(pktbuf, &bufsize, size);

  if (size < sizeof(*ip6hdr))
    return -1;

  memcpy(pktbuf, buffer, size);
  ip6hdr = (struct ip6_hdr *)pktbuf;

  hdrsize = sizeof(struct ip6_hdr);
  paysize = ntohs(ip6hdr->ip6_plen);

  PRINT(fp, pp, 1, "IPv6");
  PRINTEQ(fp, pp, 1, ":");
  PRINT(fp, pp, 3, "\tpayload size\t: %d bytes\n", paysize);
  PRINT(fp, pp, 3, "\thop limit\t: %d\n", ip6hdr->ip6_hlim);
  PRINT(fp, pp, 2, "\tsrc/dst addr\t: ");
  if (inet_ntop(AF_INET6, &ip6hdr->ip6_src, addrs, sizeof(addrs)) != NULL)
    PRINT(fp, pp, 2, "%s", addrs);
  PRINT(fp, pp, 2, " / ");
  if (inet_ntop(AF_INET6, &ip6hdr->ip6_dst, addrs, sizeof(addrs)) != NULL)
    PRINT(fp, pp, 2, "%s", addrs);
  PRINT(fp, pp, 2, "\n");

  p = pktbuf + hdrsize;
  s = size   - hdrsize;

  nexthdr = ip6hdr->ip6_nxt;

  while (1) {
    PRINT(fp, pp, 3, "\tnext header\t: %d", nexthdr);
    exthdrsize = 0;
    switch (nexthdr) {
    case IPPROTO_HOPOPTS:
      if (s < sizeof(*ip6exthdr))
	return -1;
      PRINT(fp, pp, 3, " (HOPOPTS)");
      ip6exthdr = (struct ip6_ext *)p;
      next_nexthdr = ip6exthdr->ip6e_nxt;
      exthdrsize = (ip6exthdr->ip6e_len + 1) << 3;
      break;
    case IPPROTO_DSTOPTS:
      if (s < sizeof(*ip6exthdr))
	return -1;
      PRINT(fp, pp, 3, " (DSTOPTS)");
      ip6exthdr = (struct ip6_ext *)p;
      next_nexthdr = ip6exthdr->ip6e_nxt;
      exthdrsize = (ip6exthdr->ip6e_len + 1) << 3;
      break;
    case IPPROTO_ROUTING:
      if (s < sizeof(*ip6rthdr))
	return -1;
      PRINT(fp, pp, 3, " (ROUTING)");
      ip6rthdr = (struct ip6_rthdr *)p;
      next_nexthdr = ip6rthdr->ip6r_nxt;
      exthdrsize = (ip6rthdr->ip6r_len + 1) << 3;
      break;
    case IPPROTO_FRAGMENT:
      if (s < sizeof(*ip6fraghdr))
	return -1;
      PRINT(fp, pp, 3, " (FRAGMENT)");
      ip6fraghdr = (struct ip6_frag *)p;
      next_nexthdr = ip6fraghdr->ip6f_nxt;
      exthdrsize = sizeof(*ip6fraghdr);
      break;
    case IPPROTO_NONE:
    default:
      break;
    }
    PRINT(fp, pp, 3, "\n");
    if (exthdrsize == 0)
      break;
    if (s < exthdrsize)
      return -1;
    PRINT(fp, pp, 3, "\texthdr size\t: %d bytes\n", exthdrsize);
    switch (nexthdr) {
    case IPPROTO_HOPOPTS:
      break;
    case IPPROTO_DSTOPTS:
      break;
    case IPPROTO_ROUTING:
      PRINT(fp, pp, 3, "\ttype\t\t: %d\n", ip6rthdr->ip6r_type);
      PRINT(fp, pp, 3, "\tsegleft\t\t: %d\n", ip6rthdr->ip6r_segleft);
      break;
    case IPPROTO_FRAGMENT:
      PRINT(fp, pp, 3, "\toffset\t\t: 0x%04x\n", ntohs(ip6fraghdr->ip6f_offlg));
      PRINT(fp, pp, 3, "\tident\t\t: 0x%08x\n", ntohl(ip6fraghdr->ip6f_ident));
      break;
    case IPPROTO_NONE:
    default:
      break;
    }
    p       += exthdrsize;
    s       -= exthdrsize;
    hdrsize += exthdrsize;
    paysize -= exthdrsize;
    nexthdr = next_nexthdr;
  }

  memset(&phdr, 0, sizeof(phdr));
  memcpy(&phdr.saddr, &ip6hdr->ip6_src, sizeof(struct in6_addr));
  memcpy(&phdr.daddr, &ip6hdr->ip6_dst, sizeof(struct in6_addr));
  phdr.len = htonl(paysize);
  phdr.nexthdr = nexthdr;
  pchksum = ip_checksum(&phdr, sizeof(phdr));

  pp->layer++;
  if (ip6fraghdr == NULL) {
    switch (nexthdr) {
    case IPPROTO_ICMPV6:
      r = analyze_icmp6(fp, p, s, pp, paysize, pchksum);
      break;
    case IPPROTO_TCP:
      r = analyze_tcp(  fp, p, s, pp, paysize, pchksum);
      break;
    case IPPROTO_UDP:
      r = analyze_udp(  fp, p, s, pp, paysize, pchksum);
      break;
    default:
      break;
    }
  }
  pp->layer--;

  if (r < 0)
    return r;

  p += r;
  r = p - pktbuf;

  s = minval(hdrsize + paysize, size) - r;
  if (s > 0) {
    print_payload(fp, p, s, pp, "IPv6");
    p += s;
    r += s;
  }

  return r;
}

static int analyze_loopback(FILE *fp, char *buffer, int size, params_t pp)
{
  char *p;
  int s, r = 0;
  pkt_uint32 family;

  if (size < sizeof(family))
    return -1;
  memcpy(&family, buffer, sizeof(family)); /* Unneed ntohl() */

  PRINT(fp, pp, 3, "Loopback\t");
  PRINT(fp, pp, 3, "type : %d (", family);
  switch (family) {
  case AF_INET:  PRINT(fp, pp, 3, "IP"); break;
  case AF_INET6: PRINT(fp, pp, 3, "IPv6"); break;
  default:       PRINT(fp, pp, 3, "Unknown" ); break;
  }
  PRINT(fp, pp, 3, ")\n");

  p = buffer + sizeof(family);
  s = size   - sizeof(family);

  pp->layer++;
  switch (family) {
  case AF_INET:  r = analyze_ip( fp, p, s, pp); break;
  case AF_INET6: r = analyze_ip6(fp, p, s, pp); break;
  default: break;
  }
  pp->layer--;

  if (r < 0)
    return r;

  p += r;
  r = p - buffer;

  s = size - r;
  if (s > 0) {
    print_payload(fp, p, s, pp, "Loopback");
    p += s;
    r += s;
  }

  return r;
}

static int analyze_ethernet(FILE *fp, char *buffer, int size, params_t pp)
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

  PRINT(fp, pp, 3, "Ethernet\t");
  PRINT(fp, pp, 3, "%s ->", ether_ntoa((struct ether_addr *)ehdr.ether_shost));
  PRINT(fp, pp, 3, " %s  ", ether_ntoa((struct ether_addr *)ehdr.ether_dhost));

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
    PRINT(fp, pp, 3, "(VLAN tag: 0x%04x) ", ntohs(vlantag.tag));
    type = ntohs(vlantag.proto);
    p += sizeof(vlantag);
    s -= sizeof(vlantag);
  }

  PRINT(fp, pp, 3, "(type: 0x%04x)\n", type);

  pp->layer++;
  switch (type) {
  case ETHERTYPE_ARP:  r = analyze_arp(fp, p, s, pp); break;
  case ETHERTYPE_IP:   r = analyze_ip( fp, p, s, pp); break;
  case ETHERTYPE_IPV6: r = analyze_ip6(fp, p, s, pp); break;
  default: break;
  }
  pp->layer--;

  if (r < 0)
    return r;

  p += r;
  r = p - buffer;

  s = size - r;
  if (s > 0) {
    print_payload(fp, p, s, pp, "Ethernet");
    p += s;
    r += s;
  }

  return r;
}

int pkt_analyze(FILE *fp, char *buffer, int size, int linktype,
		struct timeval *tm, int low_layer, int high_layer, int level)
{
  char *p;
  int s, r = 0;
  time_t t;
  static int count = 0;
  static int oldlinktype = DLT_UNDEFINED;
  struct print_params params;
  params_t pp = &params;

  pp->low_layer = low_layer;
  pp->high_layer = high_layer;
  pp->layer = 0;
  pp->level = level;

  if (linktype != oldlinktype) {
    PRINT(fp, pp, 2, "LINKTYPE: %d (", linktype);
    switch (linktype) {
    case DLT_EN10MB: PRINT(fp, pp, 2, "Ethernet"); break;
    case DLT_NULL:   PRINT(fp, pp, 2, "Loopback"); break;
    default:         PRINT(fp, pp, 2, "Unknown" ); break;
    }
    PRINT(fp, pp, 2, ")\n");
    oldlinktype = linktype;
  }

  count++;
  PRINT(fp, pp, 0, "-- %d --", count);
  PRINTEQ(fp, pp, 1, " ");
  PRINT(fp, pp, 2, "\n");
  t = tm->tv_sec;

  pp->layer++;

  PRINT(fp, pp, 3, "received: %d bytes    %d.%06d %s", size,
	(int)tm->tv_sec, (int)tm->tv_usec, ctime(&t));

  p = buffer;
  s = size;

  pp->layer++;
  switch (linktype) {
  case DLT_NULL:   r = analyze_loopback(fp, p, s, pp); break;
  case DLT_EN10MB: r = analyze_ethernet(fp, p, s, pp); break;
  default: break;
  }
  pp->layer--;

  if (r < 0)
    goto ret;

  p += r;
  r = p - buffer;

  s = size - r;
  if (s > 0) {
    print_payload(fp, p, s, pp, "Unknown");
    p += s;
    r += s;
  }

ret:
  pp->layer = 0;
  PRINTEQ(fp, pp, 1, "\n");
  PRINT(fp, pp, 3, "==\n");
  fflush(fp);

  return r;
}
