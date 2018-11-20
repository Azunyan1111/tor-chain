#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#ifdef USE_PKTLIB
#include "pktlib.h"
#endif
#include "pktbuf.h"

#define PKTBUF_BUFFER_SIZE (80*1024)

struct pktbuf_area { /* バッファ領域 */
  struct pktbuf_area *next;
  int ref_counter; /* リファレンス・カウンタ */
  char buffer[PKTBUF_BUFFER_SIZE];
};

struct _pktbuf { /* パケットバッファのヘッダ */
  struct _pktbuf *next; /* 次のパケットバッファ */
  struct _pktbuf *tail; /* 先頭パケットの場合は，リンクリストの終端を指す */
  struct timeval t;
  char *header; /* ヘッダ位置を指すポインタ */
  int size;
  void *option; /* オプション領域へのポインタ */
  struct pktbuf_area *area; /* バッファ領域を指す */
};

static int optsize = 0; /* オプション領域のサイズ */
static pktbuf_t pktbuf_free = NULL; /* 再利用のための解放済みリスト */
static struct pktbuf_area *area_free = NULL; /* 再利用のための解放済みリスト */

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

  if (pktbuf_free) { /* 解放済みリストから取得 */
    pktbuf = pktbuf_free;
    pktbuf_free = pktbuf_free->next;
  } else { /* 解放済みリストが空なので，新規にメモリ獲得する */
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

  if (area_free) { /* 解放済みリストから取得 */
    area = area_free;
    area_free = area_free->next;
  } else { /* 解放済みリストが空なので，新規にメモリ獲得する */
    area = malloc(sizeof(*area));
  }
  memset(area, 0, sizeof(*area));

  area->next = NULL;
  area->ref_counter = 0;

  pktbuf->next   = NULL; /* 単一のバッファ */
  pktbuf->tail   = pktbuf; /* 単一のバッファなので，終端は自分自身を指す */
  pktbuf->t.tv_sec  = 0;
  pktbuf->t.tv_usec = 0;
  pktbuf->size   = 0;
  pktbuf->option = (optsize > 0) ? (pktbuf + 1) : NULL;
  pktbuf->area   = area;
  area->ref_counter++; /* ヘッダからリンクされたのでカウンタを増加 */

  pktbuf->header = pktbuf->area->buffer;
  pktbuf->header += (offset < 0) ? PKTBUF_BUFFER_SIZE : 0;
  pktbuf->header += (offset == -1) ? 0 : offset; /* -1の場合は終端を指す */

  return pktbuf;
}

pktbuf_t pktbuf_destroy(pktbuf_t pktbuf)
{
  struct pktbuf_area *area;

  if (pktbuf) {
    area = pktbuf->area;
    pktbuf->area = NULL;
    area->ref_counter--; /* リンクが外れたのでカウンタを減少 */

    if (area->ref_counter == 0) { /* カウンタがゼロのときのみ解放処理を行う */
      area->next = area_free; /* 解放済みリストに接続する */
      area_free = area;
    }

    pktbuf->next = pktbuf_free; /* 解放済みリストに接続する */
    pktbuf_free = pktbuf;
  }

  return NULL;
}

pktbuf_t pktbuf_destroy_queue(pktbuf_t pktbuf)
{
  pktbuf_t p;
  while (pktbuf) { /* リンクリストで与えられたバッファをすべて解放する */
    p = pktbuf_dequeue(&pktbuf);
    pktbuf_destroy(p);
  }
  return NULL;
}

pktbuf_t pktbuf_clone(pktbuf_t pktbuf)
{
  pktbuf_t clone;

  clone = get_pktbuf();

  clone->next   = NULL; /* 単一のバッファ */
  clone->tail   = clone; /* 単一のバッファなので，終端は自分自身を指す */
  clone->t      = pktbuf->t;
  clone->header = pktbuf->header;
  clone->size   = pktbuf->size;
  clone->option = (optsize > 0) ? (clone + 1) : 0;
  clone->area   = pktbuf->area; /* バッファ領域は同一領域を指す */
  clone->area->ref_counter++; /* ヘッダからリンクされたのでカウンタを増加 */
  if (optsize > 0) /* オプション領域をコピーする */
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
  if (optsize > 0) /* オプション領域をコピーする */
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
  pktbuf->header -= size; /* ヘッダを前方に拡張 */
  pktbuf->size += size; /* ヘッダを拡張したのでサイズも増加させる */
  return pktbuf->header; /* 拡張後の先頭位置を返す */
}

char *pktbuf_delete_header(pktbuf_t pktbuf, int size)
{
  pktbuf->header += size; /* ヘッダを削除 */
  pktbuf->size -= size; /* ヘッダを削除したのでサイズも減少させる */
  return pktbuf->header; /* 削除後の先頭位置を返す */
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
  if (*pp) pp = &(*pp)->tail->next; /* ポインタをキューの終端に設定 */
  *pp = pktbuf; /* キューの終端に追加(キューを追加することも可能) */
  if (pktbuf)
    (*queue)->tail = pktbuf->tail; /* キューの終端を再設定する */
  return *queue;
}

pktbuf_t pktbuf_dequeue(pktbuf_t *queue)
{
  pktbuf_t pktbuf;
  pktbuf = *queue; /* キューの先端からパケットを取得する */
  if (*queue) { /* キューが空じゃなかった場合 */
    *queue = (*queue)->next;
    if (*queue) (*queue)->tail = pktbuf->tail; /* 終端を再設定する */
    pktbuf->next = NULL; /* 単一のバッファ */
    pktbuf->tail = pktbuf; /* 単一のバッファなので，終端は自分自身を指す */
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
  pktbuf->t.tv_sec  = t.tv_sec; /* 受信時刻を設定 */
  pktbuf->t.tv_usec = t.tv_usec;
  pktbuf->size = r; /* サイズを設定 */

  return pktbuf;
}

pktbuf_t pktbuf_send(pktif_t pktif, pktbuf_t pktbuf)
{
  int r;

  r = pktif_send(pktif, pktbuf->header, pktbuf->size);
  if (r < 0) /* 送信に失敗したら，パケットバッファをそのまま返す */
    return pktbuf;

  return pktbuf_destroy(pktbuf); /* 送信成功なら解放する */
}

pktbuf_t pktbuf_send_queue(pktif_t pktif, pktbuf_t pktbuf)
{
  pktbuf_t p, reply = NULL;
  while (pktbuf) { /* リンクリストで与えられたバッファをすべて送信する */
    p = pktbuf_dequeue(&pktbuf);
    p = pktbuf_send(pktif, p);
    if (p) pktbuf_enqueue(&reply, p); /* 送信失敗したパケットはリストに移動 */
  }
  return reply; /* 送信失敗したパケットのリストを返す */
}
#endif
