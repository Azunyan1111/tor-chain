#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#ifdef USE_PKTLIB
#include "pktlib.h"
#endif
#include "pktbuf.h"

#define PKTBUF_BUFFER_SIZE (80*1024)

struct pktbuf_area { /* �Хåե��ΰ� */
  struct pktbuf_area *next;
  int ref_counter; /* ��ե���󥹡������� */
  char buffer[PKTBUF_BUFFER_SIZE];
};

struct _pktbuf { /* �ѥ��åȥХåե��Υإå� */
  struct _pktbuf *next; /* ���Υѥ��åȥХåե� */
  struct _pktbuf *tail; /* ��Ƭ�ѥ��åȤξ��ϡ���󥯥ꥹ�Ȥν�ü��ؤ� */
  struct timeval t;
  char *header; /* �إå����֤�ؤ��ݥ��� */
  int size;
  void *option; /* ���ץ�����ΰ�ؤΥݥ��� */
  struct pktbuf_area *area; /* �Хåե��ΰ��ؤ� */
};

static int optsize = 0; /* ���ץ�����ΰ�Υ����� */
static pktbuf_t pktbuf_free = NULL; /* �����ѤΤ���β����Ѥߥꥹ�� */
static struct pktbuf_area *area_free = NULL; /* �����ѤΤ���β����Ѥߥꥹ�� */

int pktbuf_init(int option_size)
{
  static int initialized = 0;
  if (!initialized) {
    optsize = option_size;
    initialized = 1;
    return 1;
  }
  return 0;
}

static pktbuf_t get_pktbuf()
{
  pktbuf_t pktbuf;
  int size;

  size = sizeof(*pktbuf) + optsize;

  if (pktbuf_free) { /* �����Ѥߥꥹ�Ȥ������ */
    pktbuf = pktbuf_free;
    pktbuf_free = pktbuf_free->next;
  } else { /* �����Ѥߥꥹ�Ȥ����ʤΤǡ������˥���������� */
    pktbuf = malloc(size);
  }
  memset(pktbuf, 0, size);

  return pktbuf;
}

pktbuf_t pktbuf_create(int offset)
{
  pktbuf_t pktbuf;
  struct pktbuf_area *area;

  pktbuf_init(0);

  pktbuf = get_pktbuf();

  if (area_free) { /* �����Ѥߥꥹ�Ȥ������ */
    area = area_free;
    area_free = area_free->next;
  } else { /* �����Ѥߥꥹ�Ȥ����ʤΤǡ������˥���������� */
    area = malloc(sizeof(*area));
  }
  memset(area, 0, sizeof(*area));

  area->next = NULL;
  area->ref_counter = 0;

  pktbuf->next   = NULL; /* ñ��ΥХåե� */
  pktbuf->tail   = pktbuf; /* ñ��ΥХåե��ʤΤǡ���ü�ϼ�ʬ���Ȥ�ؤ� */
  pktbuf->t.tv_sec  = 0;
  pktbuf->t.tv_usec = 0;
  pktbuf->size   = 0;
  pktbuf->option = (optsize > 0) ? (pktbuf + 1) : NULL;
  pktbuf->area   = area;
  area->ref_counter++; /* �إå������󥯤��줿�Τǥ����󥿤����� */

  pktbuf->header = pktbuf->area->buffer;
  pktbuf->header += (offset < 0) ? PKTBUF_BUFFER_SIZE : 0;
  pktbuf->header += (offset == -1) ? 0 : offset; /* -1�ξ��Ͻ�ü��ؤ� */

  return pktbuf;
}

pktbuf_t pktbuf_destroy(pktbuf_t pktbuf)
{
  struct pktbuf_area *area;

  if (pktbuf) {
    area = pktbuf->area;
    pktbuf->area = NULL;
    area->ref_counter--; /* ��󥯤����줿�Τǥ����󥿤򸺾� */

    if (area->ref_counter == 0) { /* �����󥿤�����ΤȤ��Τ߲���������Ԥ� */
      area->next = area_free; /* �����Ѥߥꥹ�Ȥ���³���� */
      area_free = area;
    }

    pktbuf->next = pktbuf_free; /* �����Ѥߥꥹ�Ȥ���³���� */
    pktbuf_free = pktbuf;
  }

  return NULL;
}

pktbuf_t pktbuf_destroy_queue(pktbuf_t pktbuf)
{
  pktbuf_t p;
  while (pktbuf) { /* ��󥯥ꥹ�Ȥ�Ϳ����줿�Хåե��򤹤٤Ʋ������� */
    p = pktbuf_dequeue(&pktbuf);
    pktbuf_destroy(p);
  }
  return NULL;
}

pktbuf_t pktbuf_clone(pktbuf_t pktbuf)
{
  pktbuf_t clone;

  clone = get_pktbuf();

  clone->next   = NULL; /* ñ��ΥХåե� */
  clone->tail   = clone; /* ñ��ΥХåե��ʤΤǡ���ü�ϼ�ʬ���Ȥ�ؤ� */
  clone->t      = pktbuf->t;
  clone->header = pktbuf->header;
  clone->size   = pktbuf->size;
  clone->option = (optsize > 0) ? (clone + 1) : 0;
  clone->area   = pktbuf->area; /* �Хåե��ΰ��Ʊ���ΰ��ؤ� */
  clone->area->ref_counter++; /* �إå������󥯤��줿�Τǥ����󥿤����� */
  if (optsize > 0) /* ���ץ�����ΰ�򥳥ԡ����� */
    memcpy(clone->option, pktbuf->option, optsize);

  return clone;
}

pktbuf_t pktbuf_copy(pktbuf_t pktbuf)
{
  pktbuf_t copy;

  copy = pktbuf_create(0);

  copy->t      = pktbuf->t;
  copy->header = copy->area->buffer + (pktbuf->header - pktbuf->area->buffer);
  copy->size   = pktbuf->size;
  if (optsize > 0) /* ���ץ�����ΰ�򥳥ԡ����� */
    memcpy(copy->option, pktbuf->option, optsize);
  memcpy(copy->area->buffer, pktbuf->area->buffer, PKTBUF_BUFFER_SIZE);

  return copy;
}

pktbuf_t pktbuf_get_next(pktbuf_t pktbuf)
{
  return pktbuf->next;
}

struct timeval *pktbuf_get_time(pktbuf_t pktbuf)
{
  return &pktbuf->t;
}

struct timeval *pktbuf_set_time(pktbuf_t pktbuf, struct timeval *t)
{
  pktbuf->t.tv_sec  = t->tv_sec;
  pktbuf->t.tv_usec = t->tv_usec;
  return &pktbuf->t;
}

char *pktbuf_get_header(pktbuf_t pktbuf)
{
  return pktbuf->header;
}

int pktbuf_get_size(pktbuf_t pktbuf)
{
  return pktbuf->size;
}

int pktbuf_set_size(pktbuf_t pktbuf, int size)
{
  return pktbuf->size = size;
}

void *pktbuf_get_option(pktbuf_t pktbuf)
{
  return pktbuf->option;
}

char *pktbuf_add_header(pktbuf_t pktbuf, int size)
{
  pktbuf->header -= size; /* �إå��������˳�ĥ */
  pktbuf->size += size; /* �إå����ĥ�����Τǥ����������ä����� */
  return pktbuf->header; /* ��ĥ�����Ƭ���֤��֤� */
}

char *pktbuf_delete_header(pktbuf_t pktbuf, int size)
{
  pktbuf->header += size; /* �إå����� */
  pktbuf->size -= size; /* �إå����������Τǥ������⸺�������� */
  return pktbuf->header; /* ��������Ƭ���֤��֤� */
}

int pktbuf_add_size(pktbuf_t pktbuf, int size)
{
  pktbuf->size += size;
  return pktbuf->size;
}

int pktbuf_delete_size(pktbuf_t pktbuf, int size)
{
  pktbuf->size -= size;
  return pktbuf->size;
}

pktbuf_t pktbuf_enqueue(pktbuf_t *queue, pktbuf_t pktbuf)
{
  pktbuf_t *pp;
  pp = queue;
  if (*pp) pp = &(*pp)->tail->next; /* �ݥ��󥿤򥭥塼�ν�ü������ */
  *pp = pktbuf; /* ���塼�ν�ü���ɲ�(���塼���ɲä��뤳�Ȥ��ǽ) */
  if (pktbuf)
    (*queue)->tail = pktbuf->tail; /* ���塼�ν�ü������ꤹ�� */
  return *queue;
}

pktbuf_t pktbuf_dequeue(pktbuf_t *queue)
{
  pktbuf_t pktbuf;
  pktbuf = *queue; /* ���塼����ü����ѥ��åȤ�������� */
  if (*queue) { /* ���塼��������ʤ��ä���� */
    *queue = (*queue)->next;
    if (*queue) (*queue)->tail = pktbuf->tail; /* ��ü������ꤹ�� */
    pktbuf->next = NULL; /* ñ��ΥХåե� */
    pktbuf->tail = pktbuf; /* ñ��ΥХåե��ʤΤǡ���ü�ϼ�ʬ���Ȥ�ؤ� */
  }
  return pktbuf;
}

#ifdef USE_PKTLIB
pktbuf_t pktbuf_recv(pktif_t pktif, int offset)
{
  pktbuf_t pktbuf;
  struct timeval t;
  int r;

  pktbuf = pktbuf_create(offset);
  r = pktif_recv(pktif, pktbuf->header, PKTBUF_BUFFER_SIZE, &t);
  if (r < 0)
    return pktbuf_destroy(pktbuf);
  pktbuf->t.tv_sec  = t.tv_sec; /* ������������� */
  pktbuf->t.tv_usec = t.tv_usec;
  pktbuf->size = r; /* ������������ */

  return pktbuf;
}

pktbuf_t pktbuf_send(pktif_t pktif, pktbuf_t pktbuf)
{
  int r;

  r = pktif_send(pktif, pktbuf->header, pktbuf->size);
  if (r < 0) /* �����˼��Ԥ����顤�ѥ��åȥХåե��򤽤Τޤ��֤� */
    return pktbuf;

  return pktbuf_destroy(pktbuf); /* ���������ʤ�������� */
}

pktbuf_t pktbuf_send_queue(pktif_t pktif, pktbuf_t pktbuf)
{
  pktbuf_t p, reply = NULL;
  while (pktbuf) { /* ��󥯥ꥹ�Ȥ�Ϳ����줿�Хåե��򤹤٤��������� */
    p = pktbuf_dequeue(&pktbuf);
    p = pktbuf_send(pktif, p);
    if (p) pktbuf_enqueue(&reply, p); /* �������Ԥ����ѥ��åȤϥꥹ�Ȥ˰�ư */
  }
  return reply; /* �������Ԥ����ѥ��åȤΥꥹ�Ȥ��֤� */
}
#endif
