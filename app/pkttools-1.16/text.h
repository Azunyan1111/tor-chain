#ifndef _PKTTOOLS_TEXT_H_INCLUDED_
#define _PKTTOOLS_TEXT_H_INCLUDED_

#define PKT_TEXT_WRITE_FLAG_DATAONLY (1<< 0)
struct timeval;
int pkt_text_read(FILE *fp, unsigned long flags, char *buffer, int size,
		  int *linktypep, int *origsizep, struct timeval *tp,
		  pkt_asm_list_t list);
int pkt_text_write(FILE *fp, unsigned long flags, char *buffer, int size,
		   int column, int linktype, int origsize, struct timeval *tp,
		   pkt_asm_list_t list);

int pkt_binary_read(FILE *fp, char *buffer, int size, int *linktypep,
		    int *origsizep, struct timeval *tp);
int pkt_binary_write(FILE *fp, char *buffer, int size, int linktype,
		     int origsize, struct timeval *tp);

int pkt_asm_list_read(pkt_asm_list_t list, pkt_asm_field_t field, FILE *fp);
int pkt_asm_list_write(pkt_asm_list_t list, FILE *fp);
int pkt_asm_list_read_args(pkt_asm_list_t list, int argc, char *argv[]);
int pkt_asm_list_filter_args(pkt_asm_list_t list, int argc, char *argv[]);

#endif
