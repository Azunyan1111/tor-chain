#ifdef __linux__
#ifndef _PKTTOOLS_RAWSOCK_H_INCLUDED_
#define _PKTTOOLS_RAWSOCK_H_INCLUDED_

struct timeval;
pktif_t rawsock_open_recv(char *ifname, unsigned long flags, int *bufsizep);
pktif_t rawsock_open_send(char *ifname, unsigned long flags);
int rawsock_get_linktype(pktif_t pktif);
int rawsock_recv(pktif_t pktif, char *buffer, int size, int *linktypep,
		 int *origsizep, struct timeval *tm);
int rawsock_send(pktif_t pktif, char *buffer, int size, int linktype,
		 int origsize, struct timeval *tm);
int rawsock_close(pktif_t pktif);

int rawsock_get_dlt(int s);
int rawsock_normalize_header(int linktype, char *buffer, int size);
int rawsock_specialize_header(int linktype, char *buffer, int size);

#endif
#endif
