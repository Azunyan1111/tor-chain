#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__) || defined(__APPLE__)
#ifndef _PKTTOOLS_BPF_H_INCLUDED_
#define _PKTTOOLS_BPF_H_INCLUDED_

struct timeval;
pktif_t bpf_open_recv(char *ifname, unsigned long flags, int *bufsizep);
pktif_t bpf_open_send(char *ifname, unsigned long flags);
int bpf_get_linktype(pktif_t pktif);
int bpf_recv(pktif_t pktif, char *buffer, int size, int *linktypep,
	     int *origsizep, struct timeval *tm);
int bpf_send(pktif_t pktif, char *buffer, int size, int linktype,
	     int origsize, struct timeval *tm);
int bpf_close(pktif_t pktif);

#endif
#endif
