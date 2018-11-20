#ifndef _PKTTOOLS_DEFRAGMENT_H_INCLUDED_
#define _PKTTOOLS_DEFRAGMENT_H_INCLUDED_

struct timeval;
int pkt_defragment(char *buffer, int size, int linktype, int origsize,
		   struct timeval *tm);
int pkt_defragment_dequeue(char *buffer, int size, int *linktypep,
			   int *origsizep, struct timeval *tm);

#endif
