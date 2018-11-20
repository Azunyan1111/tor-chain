#ifdef __linux__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#ifndef USE_NETLIB
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#endif

#include "defines.h"
#ifdef USE_NETLIB
#include <netlib.h>
#endif

#include "rawsock.h"
#include "lib.h"

#ifndef USE_NETLIB
struct pktif {
  unsigned long flags;
  int s;
  int ifindex;
  int linktype;

  struct {
    int dummy;
  } recv;

  struct {
    char macaddr_src[ETHER_ADDR_LEN];
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

  return pktif;
}

static pktif_t pktif_destroy(pktif_t pktif)
{
  if (pktif) {
    free(pktif);
  }
  return NULL;
}

static int flush_recv_buffer(int s, int size)
{
  fd_set fds;
  struct timeval timeout;
  char *buffer = NULL;
  int r;

  while (size > 0) {
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    timeout.tv_sec = timeout.tv_usec = 0;
    r = select(s + 1, &fds, NULL, NULL, &timeout);
    if (r < 0) continue;
    if ((r == 0) || ((r > 0) && !FD_ISSET(s, &fds)))
      break;
    if (buffer == NULL) {
      buffer = malloc(size);
      if (buffer == NULL)
	error_exit("Out of memory.\n");
    }
    r = recv(s, buffer, size, 0);
    if (r < 0)
      error_exit("Cannot flush buffer.\n");
    if (r == 0)
      break;
    size =- r;
  }

  if (buffer) free(buffer);

  return 0;
}

pktif_t rawsock_open_recv(char *ifname, unsigned long flags, int *bufsizep)
{
  pktif_t pktif;
  int s, bufsize;
  struct ifreq ifr;
  struct sockaddr_ll sll;
  struct packet_mreq mreq;
  int optval;
  socklen_t optlen;

  pktif = pktif_create();

  pktif->flags = flags;

  s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (s < 0)
    error_exit("Cannot open raw socket.\n");

  pktif->s = s;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  if (ioctl(s, SIOCGIFINDEX, &ifr) < 0)
    error_exit("Fail to ioctl SIOCGIFINDEX.\n");
  pktif->ifindex = ifr.ifr_ifindex;

  optlen = sizeof(optval);
  if (getsockopt(s, SOL_SOCKET, SO_RCVBUF, &optval, &optlen) < 0)
    error_exit("Fail to getsockopt SO_RCVBUF.\n");
  bufsize = optval / 2;

  if (flags & PKT_RECV_FLAG_PROMISC) {
    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_type = PACKET_MR_PROMISC;
    mreq.mr_ifindex = pktif->ifindex;
    if (setsockopt(s, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
		   &mreq, sizeof(mreq)) < 0)
      error_exit("Fail to setsockopt PACKET_ADD_MEMBERSHIP.\n");
  }

  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_ALL);
  sll.sll_ifindex = pktif->ifindex;
  if (bind(s, (struct sockaddr *)&sll, sizeof(sll)) < 0)
    error_exit("Cannot bind.\n");

  pktif->linktype = rawsock_get_dlt(s);

  flush_recv_buffer(s, bufsize);

  if (bufsizep) *bufsizep = bufsize;

  return pktif;
}

pktif_t rawsock_open_send(char *ifname, unsigned long flags)
{
  pktif_t pktif;
  int s;
  struct ifreq ifr;
  struct sockaddr_ll sll;

  pktif = pktif_create();

  pktif->flags = flags;

  s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (s < 0)
    error_exit("Cannot open raw socket.\n");

  pktif->s = s;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  if (ioctl(s, SIOCGIFINDEX, &ifr) < 0)
    error_exit("Fail to ioctl SIOCGIFINDEX.\n");
  pktif->ifindex = ifr.ifr_ifindex;

  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_ALL);
  sll.sll_ifindex = pktif->ifindex;
  if (bind(s, (struct sockaddr *)&sll, sizeof(sll)) < 0)
    error_exit("Cannot bind.\n");

  pktif->linktype = rawsock_get_dlt(s);

  if (flags & PKT_SEND_FLAG_COMPLETE) {
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0)
      error_exit("Fail to ioctl SIOCGIFHWADDR.\n");
    memcpy(pktif->send.macaddr_src, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
  }

  return pktif;
}

int rawsock_get_linktype(pktif_t pktif)
{
  return pktif->linktype;
}

int rawsock_recv(pktif_t pktif, char *buffer, int size, int *linktypep,
		 int *origsizep, struct timeval *tm)
{
  int r;
  socklen_t optlen;
  struct sockaddr_ll sll;
  struct timeval t;

  while (1) {
    optlen = sizeof(sll);
    r = recvfrom(pktif->s, buffer, size, 0, (struct sockaddr *)&sll, &optlen);
    /*
     * If interface is linkdown, block reading and can restart when recovered.
     * If interface is down, -1 is returned.
     * If set signal handler and signaled, but blocking is not canceled.
     */
    if (r < 0)
      error_exit("Interface down.\n");
    if (r == 0)
      error_exit("Interface is unknown status.\n");
    if (r >= size)
      error_exit("Out of buffer.\n");

    if (pktif->flags & PKT_RECV_FLAG_RECVONLY) {
      if (pktif->flags & PKT_RECV_FLAG_SENDONLY)
	break;
      if (sll.sll_pkttype != PACKET_OUTGOING)
	break;
    } else if (pktif->flags & PKT_RECV_FLAG_SENDONLY) {
      if (sll.sll_pkttype == PACKET_OUTGOING)
	break;
    } else {
      break;
    }
  }

  if (tm) {
    if (ioctl(pktif->s, SIOCGSTAMP, &t) < 0)
      error_exit("Cannot get timestamp.\n");
    tm->tv_sec  = t.tv_sec;
    tm->tv_usec = t.tv_usec;
  }

  r = rawsock_normalize_header(pktif->linktype, buffer, r);

  if (linktypep) *linktypep = pktif->linktype;
  if (origsizep) *origsizep = r;

  return r;
}

int rawsock_send(pktif_t pktif, char *buffer, int size, int linktype,
		 int origsize, struct timeval *tm)
{
  int r;
  struct sockaddr_ll sll;
  struct ether_header *ehdr;
  char macaddr_save[ETHER_ADDR_LEN];
  int complete = 0;
  char *p;
  int s;
  char sendbuf[ETHER_MIN_LEN - ETHER_CRC_LEN];

  ehdr = (struct ether_header *)buffer;

  r = rawsock_specialize_header(linktype, buffer, size);
  origsize += (r - size);
  size = r;

  if (pktif->linktype == DLT_EN10MB) {
    if ((pktif->flags & PKT_SEND_FLAG_COMPLETE) && (size >= ETHER_HDR_LEN)) {
      complete = 1;
    }
  }
  if (complete) {
    memcpy(macaddr_save, ehdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(ehdr->ether_shost, pktif->send.macaddr_src, ETHER_ADDR_LEN);
  }

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

  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = pktif->ifindex;
  r = sendto(pktif->s, p, s, 0, (struct sockaddr *)&sll, sizeof(sll));

  if (complete) {
    memcpy(ehdr->ether_shost, macaddr_save, ETHER_ADDR_LEN);
  }

  return r;
}

int rawsock_close(pktif_t pktif)
{
  close(pktif->s);
  pktif_destroy(pktif);
  return 0;
}
#endif

static int arptype2dlt(int arptype)
{
  int dlt = DLT_UNKNOWN;

#ifndef ARPHRD_FDDI
#define ARPHRD_FDDI 774
#endif
#ifndef ARPHRD_ATM
#define ARPHRD_ATM 19
#endif
#ifndef ARPHRD_IEEE80211
#define ARPHRD_IEEE80211 801
#endif
#ifndef ARPHRD_IEEE80211_PRISM
#define ARPHRD_IEEE80211_PRISM 802
#endif
#ifndef ARPHRD_IEEE80211_RADIOTAP
#define ARPHRD_IEEE80211_RADIOTAP 803
#endif
#ifndef ARPHRD_NONE
#define ARPHRD_NONE 0xFFFE
#endif

  switch (arptype) {
  case ARPHRD_ETHER:    dlt = DLT_EN10MB;      break;
  case ARPHRD_LOOPBACK: dlt = DLT_NULL;        break; /* Need cook packet */
  case ARPHRD_EETHER:   dlt = DLT_EN3MB;       break;
  case ARPHRD_AX25:     dlt = DLT_AX25;        break; /* DLT_AX25_KISS? */
  case ARPHRD_PRONET:   dlt = DLT_PRONET;      break;
  case ARPHRD_CHAOS:    dlt = DLT_CHAOS;       break;
  case ARPHRD_IEEE802:  dlt = DLT_IEEE802;     break;
  case ARPHRD_ARCNET:   dlt = DLT_ARCNET;      break; /* DLT_ARCNET_LINUX? */
  case ARPHRD_FDDI:     dlt = DLT_FDDI;        break;
  case ARPHRD_ATM:      dlt = DLT_ATM_RFC1483; break; /* DLT_LINUX_SLL? */
  case ARPHRD_IEEE80211:          dlt = DLT_IEEE802_11;       break;
  case ARPHRD_IEEE80211_PRISM:    dlt = DLT_PRISM_HEADER;     break;
  case ARPHRD_IEEE80211_RADIOTAP: dlt = DLT_IEEE802_11_RADIO; break;
  case ARPHRD_SLIP:     dlt = DLT_SLIP;        break; /* DLT_RAW? */

  case ARPHRD_PPP: /* Need check */
  case ARPHRD_TUNNEL:
  case ARPHRD_NONE:
    dlt = DLT_RAW;
    break;

  default:
    break;
  }

  return dlt;
}

int rawsock_get_dlt(int s)
{
  struct sockaddr_ll sll;
  socklen_t optlen;

  memset(&sll, 0, sizeof(sll));
  optlen = sizeof(sll);
  if (getsockname(s, (struct sockaddr *)&sll, &optlen) < 0)
    error_exit("Cannot getsockname.\n");

  return arptype2dlt(sll.sll_hatype);
}

int rawsock_normalize_header(int linktype, char *buffer, int size)
{
  struct ether_header ehdr;
  pkt_uint32 family;

  if (linktype == DLT_NULL) {
    if (size >= ETHER_HDR_LEN) {
      memcpy(&ehdr, buffer, ETHER_HDR_LEN);

      memmove(buffer + sizeof(family), buffer + ETHER_HDR_LEN,
	      size - ETHER_HDR_LEN);
      size -= (ETHER_HDR_LEN - sizeof(family));

      family = ethertype2af(ntohs(ehdr.ether_type));
      memcpy(buffer, &family, sizeof(family)); /* Unneed htonl() */
    }
  }

  return size;
}

int rawsock_specialize_header(int linktype, char *buffer, int size)
{
  struct ether_header ehdr;
  pkt_uint32 family;

  if (linktype == DLT_NULL) {
    if (size >= sizeof(family)) {
      memcpy(&family, buffer, sizeof(family)); /* Unneed ntohl() */

      memmove(buffer + ETHER_HDR_LEN, buffer + sizeof(family),
	      size - sizeof(family));
      size += (ETHER_HDR_LEN - sizeof(family));

      memset(&ehdr, 0, ETHER_HDR_LEN);
      ehdr.ether_type = htons(af2ethertype(family));
      memcpy(buffer, &ehdr, ETHER_HDR_LEN);
    }
  }

  return size;
}
#endif
