#ifndef _PKTLIB_PKTBUF_H_INCLUDED_
#define _PKTLIB_PKTBUF_H_INCLUDED_

typedef struct _pktbuf *pktbuf_t;

/* ������� */
int pktbuf_init(int option_size);

/* �Хåե��������Ⱦõ� */
pktbuf_t pktbuf_create(int offset);
pktbuf_t pktbuf_destroy(pktbuf_t pktbuf);
pktbuf_t pktbuf_destroy_queue(pktbuf_t pktbuf);
pktbuf_t pktbuf_clone(pktbuf_t pktbuf);
pktbuf_t pktbuf_copy(pktbuf_t pktbuf);

/* �ѥ�᡼������������ */
pktbuf_t pktbuf_get_next(pktbuf_t pktbuf);
struct timeval *pktbuf_get_time(pktbuf_t pktbuf);
struct timeval *pktbuf_set_time(pktbuf_t pktbuf, struct timeval *t);
char *pktbuf_get_header(pktbuf_t pktbuf);
int pktbuf_get_size(pktbuf_t pktbuf);
int pktbuf_set_size(pktbuf_t pktbuf, int size);
void *pktbuf_get_option(pktbuf_t pktbuf);

/* �ΰ�γ�ĥ�Ⱥ�� */
char *pktbuf_add_header(pktbuf_t pktbuf, int size);
char *pktbuf_delete_header(pktbuf_t pktbuf, int size);
int pktbuf_add_size(pktbuf_t pktbuf, int size);
int pktbuf_delete_size(pktbuf_t pktbuf, int size);

/* ���塼��� */
pktbuf_t pktbuf_enqueue(pktbuf_t *queue, pktbuf_t pktbuf);
pktbuf_t pktbuf_dequeue(pktbuf_t *queue);

#ifdef USE_PKTLIB
/* pktif��Ȥä��ѥ��åȤ������� */
pktbuf_t pktbuf_recv(pktif_t pktif, int offset);
pktbuf_t pktbuf_send(pktif_t pktif, pktbuf_t pktbuf);
pktbuf_t pktbuf_send_queue(pktif_t pktif, pktbuf_t pktbuf);

/* �����å�����׻� */
pktbuf_t pktbuf_checksum_correct_ip(pktbuf_t pktbuf);
pktbuf_t pktbuf_checksum_correct(pktbuf_t pktbuf);
#endif

#endif
