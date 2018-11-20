#ifdef USE_LIBPCAP
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>

#include "defines.h"

#ifdef __linux__
#include "rawsock.h"
#endif
#include "libpcap.h"
#include "lib.h"

struct pktif {
  unsigned long flags;
  pcap_t *pcap_handle;
  int linktype;
  int bufsize;
  char errbuf[PCAP_ERRBUF_SIZE];
#ifdef USE_WINPCAP
  char *ifname;
#endif

  struct {
    int dummy;
  } recv;

  struct {
    int dummy;
  } send;
};

static pktif_t pktif_create()
{
  pktif_t pktif;

  pktif = malloc(sizeof(*pktif));
  if (pktif == NULL)
    error_exit("Cannot allocate memory.\n");
  memset(pktif, 0, sizeof(*pktif));

  pktif->flags = 0;
  pktif->bufsize = 65536;
#ifdef USE_WINPCAP
  pktif->ifname = NULL;
#endif

  return pktif;
}

static pktif_t pktif_destroy(pktif_t pktif)
{
  if (pktif) {
#ifdef USE_WINPCAP
    if (pktif->ifname) free(pktif->ifname);
#endif
    free(pktif);
  }
  return NULL;
}

#ifdef USE_WINPCAP
static char *interface_search(pktif_t pktif, char *ifname)
{
  pcap_if_t *alldevs;
  pcap_if_t *d;
  int i, n = -1;

  if (ifname) n = atoi(ifname);

  if (pcap_findalldevs(&alldevs, pktif->errbuf) < 0)
    error_exit("Cannot find devices.\n");

  if (n < 0) {
    fprintf(stderr, "Available interface list:\n");
  }

  i = 0;
  for (d = alldevs; d; d = d->next) {
    if (n < 0) {
      fprintf(stderr, "\t%d\t%s\n\t\t%s\n", i,
	      d->description ? d->description : "No description",
	      d->name);
    } else {
      if (i == n) {
	pktif->ifname = strdup(d->name);
	break;
      }
    }
    i++;
  }

  pcap_freealldevs(alldevs);

  return pktif->ifname;
}
#endif

pktif_t libpcap_open_recv(char *ifname, unsigned long flags, int *bufsizep)
{
  pktif_t pktif;
  pcap_t *pcap_handle;

  pktif = pktif_create();

  pktif->flags = flags;

#ifdef USE_WINPCAP
  ifname = interface_search(pktif, ifname);
  if (ifname == NULL)
    error_exit("Unknown interface.\n");
#endif

  pcap_handle = pcap_open_live(ifname, pktif->bufsize,
			       (flags & PKT_RECV_FLAG_PROMISC) ? 1 : 0,
			       50, pktif->errbuf);
  if (pcap_handle == NULL)
    error_exit("Cannot open libpcap.\n");

  pktif->pcap_handle = pcap_handle;

#ifndef __linux__
  pktif->linktype = pcap_datalink(pcap_handle);
#else
  pktif->linktype = rawsock_get_dlt(pcap_fileno(pcap_handle));
#endif

  if (flags & PKT_RECV_FLAG_RECVONLY) {
    if (!(flags & PKT_RECV_FLAG_SENDONLY)) {
      if (pcap_setdirection(pcap_handle, PCAP_D_IN) < 0)
	error_exit("Fail to libpcap setdirection.\n");
    }
  } else if (flags & PKT_RECV_FLAG_SENDONLY) {
    if (pcap_setdirection(pcap_handle, PCAP_D_OUT) < 0)
      error_exit("Fail to libpcap setdirection.\n");
  }

  if (bufsizep) *bufsizep = pktif->bufsize;

  return pktif;
}

pktif_t libpcap_open_send(char *ifname, unsigned long flags)
{
  pktif_t pktif;
  pcap_t *pcap_handle;

  pktif = pktif_create();

  pktif->flags = flags;

#ifdef USE_WINPCAP
  ifname = interface_search(pktif, ifname);
  if (ifname == NULL)
    error_exit("Unknown interface.\n");
#endif

  pcap_handle = pcap_open_live(ifname, pktif->bufsize, 0, 0, pktif->errbuf);
  if (pcap_handle == NULL)
    error_exit("Cannot open libpcap.\n");

  pktif->pcap_handle = pcap_handle;

#ifndef __linux__
  pktif->linktype = pcap_datalink(pcap_handle);
#else
  pktif->linktype = rawsock_get_dlt(pcap_fileno(pcap_handle));
#endif

  if (flags & PKT_SEND_FLAG_COMPLETE) {
    error_exit("Unsupported -c option with libpcap.\n");
  }

  return pktif;
}

int libpcap_get_linktype(pktif_t pktif)
{
  return pktif->linktype;
}

struct recv_userdata {
  struct pcap_pkthdr *header;
  const unsigned char **buffer;
};

static void recv_proc(unsigned char *user,
		      const struct pcap_pkthdr *header,
		      const unsigned char *buffer)
{
  struct recv_userdata *rud = (struct recv_userdata *)user;
  memcpy(rud->header, header, sizeof(*(rud->header)));
  *(rud->buffer) = buffer;
}

int libpcap_recv(pktif_t pktif, char *buffer, int size, int *linktypep,
		 int *origsizep, struct timeval *tm)
{
  int r;
  const unsigned char *pktbuf;
  struct pcap_pkthdr header;
  struct recv_userdata rud;

  rud.header = &header;
  rud.buffer = &pktbuf;
  r = pcap_loop(pktif->pcap_handle, 1, recv_proc, (unsigned char *)&rud);
  if (r < 0)
    error_exit("Interface down.\n");

  if (tm) {
    tm->tv_sec  = header.ts.tv_sec;
    tm->tv_usec = header.ts.tv_usec;
  }
  r = header.caplen;
  if (r >= size)
    error_exit("Out of buffer.\n");
  memcpy(buffer, pktbuf, r);

  if (linktypep) *linktypep = pktif->linktype;
  if (origsizep) *origsizep = header.len;

#ifdef __linux__
  size = r;
  r = rawsock_normalize_header(pktif->linktype, buffer, size);
  *origsizep += (r - size);
#endif

  return r;
}

int libpcap_send(pktif_t pktif, char *buffer, int size, int linktype,
		 int origsize, struct timeval *tm)
{
  int r;
  char *p;
  int s;
  char sendbuf[ETHER_MIN_LEN - ETHER_CRC_LEN];

#ifdef __linux__
  r = rawsock_specialize_header(linktype, buffer, size);
  origsize += (r - size);
  size = r;
#endif

  p = buffer;
  s = size;
  if (pktif->linktype == DLT_EN10MB) {
    if (size < ETHER_MIN_LEN - ETHER_CRC_LEN) {
      memcpy(sendbuf, buffer, size);
      memset(sendbuf + size, 0, sizeof(sendbuf) - size);
      p = sendbuf;
      s = ETHER_MIN_LEN - ETHER_CRC_LEN;
    }
  }

  r = pcap_sendpacket(pktif->pcap_handle, (unsigned char *)p, s);
  r = (r < 0) ? -1 : size;

  return r;
}

int libpcap_close(pktif_t pktif)
{
  pcap_close(pktif->pcap_handle);
  pktif_destroy(pktif);
  return 0;
}
#endif
