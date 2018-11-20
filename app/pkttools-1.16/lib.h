#ifndef _PKTTOOLS_LIB_H_INCLUDED_
#define _PKTTOOLS_LIB_H_INCLUDED_

#define PKT_BUFFER_SIZE_DEFAULT 0x14000 /* 80KB */

#define PKT_RECV_FLAG_PROMISC  (1<< 0)
#define PKT_RECV_FLAG_RECVONLY (1<< 1)
#define PKT_RECV_FLAG_SENDONLY (1<< 2)
#define PKT_SEND_FLAG_COMPLETE (1<<16)
#define PKT_SEND_FLAG_INTERVAL (1<<17)

struct timeval;

struct pkt_handler {
  pktif_t (*open_recv)(char *ifname, unsigned long flags, int *bufsizep);
  pktif_t (*open_send)(char *ifname, unsigned long flags);
  int (*get_linktype)(pktif_t pktif);
  int (*recv)(pktif_t pktif, char *buffer, int size, int *linktypep,
	      int *origsizep, struct timeval *tm);
  int (*send)(pktif_t pktif, char *buffer, int size, int linktype,
	      int origsize, struct timeval *tm);
  int (*close)(pktif_t pktif);
};

extern struct pkt_handler pkthandler;

int minval(int v0, int v1);
int maxval(int v0, int v1);

int ip_checksum(void *buffer, int size);

#define DLT_UNDEFINED         -1
#define DLT_UNKNOWN       0xFFFF

#ifndef DLT_NULL
#define DLT_NULL               0
#endif
#ifndef DLT_EN10MB
#define DLT_EN10MB             1
#endif
#ifndef DLT_EN3MB
#define DLT_EN3MB              2
#endif
#ifndef DLT_AX25
#define DLT_AX25               3
#endif
#ifndef DLT_PRONET
#define DLT_PRONET             4
#endif
#ifndef DLT_CHAOS
#define DLT_CHAOS              5
#endif
#ifndef DLT_IEEE802
#define DLT_IEEE802            6
#endif
#ifndef DLT_ARCNET
#define DLT_ARCNET             7
#endif
#ifndef DLT_SLIP
#define DLT_SLIP               8
#endif
#ifndef DLT_PPP
#define DLT_PPP                9
#endif
#ifndef DLT_FDDI
#define DLT_FDDI              10
#endif
#ifndef DLT_ATM_RFC1483
#define DLT_ATM_RFC1483       11
#endif
#ifndef DLT_RAW
#define DLT_RAW               12
#endif
#ifndef DLT_IEEE802_11
#define DLT_IEEE802_11       105
#endif
#ifndef DLT_PRISM_HEADER
#define DLT_PRISM_HEADER     119
#endif
#ifndef DLT_IEEE802_11_RADIO
#define DLT_IEEE802_11_RADIO 127
#endif
#ifndef DLT_ARCNET_LINUX
#define DLT_ARCNET_LINUX     129
#endif
#ifndef DLT_AX25_KISS
#define DLT_AX25_KISS        202
#endif

#ifndef ETHER_CRC_LEN
#define ETHER_CRC_LEN 4
#endif
#ifndef ETHER_MIN_LEN
#define ETHER_MIN_LEN 64
#endif

int ethertype2af(int ethertype);
int af2ethertype(int af);

#ifdef __linux__
/*
 * ether_ntoa() of glibc may display MAC address by 1 digit.
 * (string format is "%x:%x:%x:%x:%x:%x")
 * Define new ether_ntoa() and use it.
 */
#define ether_ntoa(n) ether_ntoa_fixed_column(n)
struct ether_addr;
char *ether_ntoa_fixed_column(const struct ether_addr *n);
#endif

void *pkt_alloc_buffer(void *buffer, int *sizep, int size);

void error_exit(char *message);

#endif
