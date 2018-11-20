#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef USE_NETLIB
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#endif

#include "defines.h"
#ifdef USE_NETLIB
#include <netlib.h>
#endif

#include "bpf.h"
#include "rawsock.h"
#include "libpcap.h"
#include "lib.h"

struct pkt_handler pkthandler = {
#ifdef USE_LIBPCAP
  libpcap_open_recv, libpcap_open_send,
  libpcap_get_linktype,
  libpcap_recv, libpcap_send, libpcap_close,
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__) || defined(__APPLE__)
  bpf_open_recv, bpf_open_send,
  bpf_get_linktype,
  bpf_recv, bpf_send, bpf_close,
#elif defined(__linux__)
  rawsock_open_recv, rawsock_open_send,
  rawsock_get_linktype,
  rawsock_recv, rawsock_send, rawsock_close,
#else
#warning Unknown plathome. Cannot use pkt-recv/pkt-send.
  NULL, NULL, NULL, NULL, NULL, NULL,
#endif
};

int minval(int v0, int v1)
{
  return (v0 < v1) ? v0 : v1;
}

int maxval(int v0, int v1)
{
  return (v0 > v1) ? v0 : v1;
}

int ip_checksum(void *buffer, int size)
{
  union {
    char c[2];
    unsigned short s;
  } w;
  char *p;
  int sum = 0;

  for (p = buffer; size > 0; p += 2) {
    w.c[0] = p[0];
    w.c[1] = (size > 1) ? p[1] : 0;
    sum += w.s; /* Unneed ntohs() */
    size -= 2;
  }
  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);

  return sum;
}

int ethertype2af(int ethertype)
{
  int af = AF_UNSPEC;

  switch (ethertype) {
  case ETHERTYPE_IP:   af = AF_INET;  break;
  case ETHERTYPE_IPV6: af = AF_INET6; break;
  default: break;
  }

  return af;
}

int af2ethertype(int af)
{
  int ethertype = 0xFFFF; /* ETHERTYPE_MAX */

  switch (af) {
  case AF_INET:  ethertype = ETHERTYPE_IP;   break;
  case AF_INET6: ethertype = ETHERTYPE_IPV6; break;
  default: break;
  }

  return ethertype;
}

#ifdef __linux__
char *ether_ntoa_fixed_column(const struct ether_addr *n)
{
  static char addr[18];
  union {
    unsigned char octet[ETHER_ADDR_LEN];
    struct ether_addr addr;
  } macaddr;

  memcpy(&macaddr.addr, n, ETHER_ADDR_LEN);
  sprintf(addr, "%02x:%02x:%02x:%02x:%02x:%02x",
	  macaddr.octet[0], macaddr.octet[1], macaddr.octet[2],
	  macaddr.octet[3], macaddr.octet[4], macaddr.octet[5]);

  return addr;
}
#endif

void *pkt_alloc_buffer(void *buffer, int *sizep, int size)
{
  if ((buffer == NULL) || (*sizep < size)) {
    if (buffer)
      free(buffer);
    buffer = malloc(size);
    if (buffer == NULL)
      error_exit("Out of memory.\n");
    *sizep = size;
  }
  return buffer;
}

void error_exit(char *message)
{
  fprintf(stderr, "%s", message);
  exit(1);
}
