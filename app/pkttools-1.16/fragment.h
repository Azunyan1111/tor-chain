#ifndef _PKTTOOLS_FRAGMENT_H_INCLUDED_
#define _PKTTOOLS_FRAGMENT_H_INCLUDED_

struct timeval;
int pkt_fragment(char *buffer, int size, int linktype, int origsize,
		 struct timeval *tm, int mtu, int force);
int pkt_fragment_dequeue(char *buffer, int size, int *linktypep,
			 int *origsizep, struct timeval *tm);

#endif
