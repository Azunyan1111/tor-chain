#ifndef _PKTTOOLS_ANALYZE_H_INCLUDED_
#define _PKTTOOLS_ANALYZE_H_INCLUDED_

struct timeval;
int pkt_analyze(FILE *fp, char *buffer, int size, int linktype,
		struct timeval *tm, int low_layer, int high_layer, int level);

#endif
