#ifndef _PKTTOOLS_PCAPNG_H_INCLUDED_
#define _PKTTOOLS_PCAPNG_H_INCLUDED_

#define PKT_PCAPNG_WRITE_FLAG_ENDIAN_MASK   (3 << 0)
#define PKT_PCAPNG_WRITE_FLAG_ENDIAN_NATIVE (0 << 0)
#define PKT_PCAPNG_WRITE_FLAG_ENDIAN_LITTLE (1 << 0)
#define PKT_PCAPNG_WRITE_FLAG_ENDIAN_BIG    (2 << 0)

struct timeval;
int pkt_pcapng_init(unsigned long flags);
int pkt_pcapng_read(FILE *fp, char *buffer, int size, int *linktypep,
		    int *origsizep, struct timeval *tm);
int pkt_pcapng_write(FILE *fp, char *buffer, int size, int linktype,
		     int origsize, struct timeval *tm);

#endif
