#ifndef _PKTTOOLS_PCAP_H_INCLUDED_
#define _PKTTOOLS_PCAP_H_INCLUDED_

#define PKT_PCAP_WRITE_FLAG_ENDIAN_MASK   (3 << 0)
#define PKT_PCAP_WRITE_FLAG_ENDIAN_NATIVE (0 << 0)
#define PKT_PCAP_WRITE_FLAG_ENDIAN_LITTLE (1 << 0)
#define PKT_PCAP_WRITE_FLAG_ENDIAN_BIG    (2 << 0)

struct timeval;
int pkt_pcap_init(unsigned long flags);
int pkt_pcap_read(FILE *fp, char *buffer, int size, int *linktypep,
		  int *origsizep, struct timeval *tm);
int pkt_pcap_write(FILE *fp, char *buffer, int size, int linktype,
		   int origsize, struct timeval *tm);

#endif
