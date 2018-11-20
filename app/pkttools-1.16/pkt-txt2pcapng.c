#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/time.h>
#ifdef WIN32
#include <fcntl.h>
#endif

#include "defines.h"

#include "argument.h"
#include "asm_val.h"
#include "asm_field.h"
#include "asm_entry.h"
#include "asm_list.h"
#include "assemble.h"
#include "disasm.h"
#include "text.h"
#include "pcapng.h"
#include "lib.h"

static void help()
{
  fprintf(stderr, "pkt-txt2pcapng\n");
  fprintf(stderr, "\tInput packets from stdin and output PcapNg file.\n\n");
  fprintf(stderr, "EXAMPLE:\n");
  fprintf(stderr, "\t$ pkt-recv -i eth0 | pkt-txt2pcapng > packet.pcapng\n");
  fprintf(stderr, "\t$ tshark -r packet.pcapng\n\n");
  fprintf(stderr, "OPTIONS:\n");
  fprintf(stderr, "\t-h\t\tOutput help of options.\n");
  fprintf(stderr, "\t-k\t\tOutput help of keys.\n");
  fprintf(stderr, "\t-b <size>\tBuffer size.\n");
  fprintf(stderr, "\t-s <count>\tSkip count.\n");
  fprintf(stderr, "\t-l <count>\tProcessing limit.\n");
  fprintf(stderr, "\t-r\t\tReverse filter rule.\n");
  fprintf(stderr, "\t-nb\t\tSkip broadcast packet.\n");
  fprintf(stderr, "\t-nm\t\tSkip multicast packet.\n");
  fprintf(stderr, "\t-lt <type>\tLink-layer type.\n");
  fprintf(stderr, "\t-ne\t\tOutput by native endian.\n");
  fprintf(stderr, "\t-le\t\tOutput by little endian.\n");
  fprintf(stderr, "\t-be\t\tOutput by big endian.\n");
  exit(0);
}

static void help_key()
{
  fprintf(stderr, "FILTER KEYS:\n");
  pkt_asm_field_output_key_list(stderr, "\t");
  exit(0);
}

static int bufsize = PKT_BUFFER_SIZE_DEFAULT;
static int skip    = 0;
static int limit   = 0;
static int filrev  = ARGUMENT_FLAG_OFF;
static int nobroad = ARGUMENT_FLAG_OFF;
static int nomulti = ARGUMENT_FLAG_OFF;
static int lltype  = DLT_UNDEFINED;
static int nendian = ARGUMENT_FLAG_OFF;
static int lendian = ARGUMENT_FLAG_OFF;
static int bendian = ARGUMENT_FLAG_OFF;

static Argument args[] = {
  { "-h" , ARGUMENT_TYPE_FUNCTION, help     },
  { "-k" , ARGUMENT_TYPE_FUNCTION, help_key },
  { "-b" , ARGUMENT_TYPE_INTEGER , &bufsize },
  { "-s" , ARGUMENT_TYPE_INTEGER , &skip    },
  { "-l" , ARGUMENT_TYPE_INTEGER , &limit   },
  { "-r" , ARGUMENT_TYPE_FLAG_ON , &filrev  },
  { "-nb", ARGUMENT_TYPE_FLAG_ON , &nobroad },
  { "-nm", ARGUMENT_TYPE_FLAG_ON , &nomulti },
  { "-lt", ARGUMENT_TYPE_INTEGER , &lltype  },
  { "-ne", ARGUMENT_TYPE_FLAG_ON , &nendian },
  { "-le", ARGUMENT_TYPE_FLAG_ON , &lendian },
  { "-be", ARGUMENT_TYPE_FLAG_ON , &bendian },
  { NULL , ARGUMENT_TYPE_NONE    , NULL     },
};

static int terminated = 0;
static void sigint_handler(int value)
{
  terminated = 1;
}

int main(int argc, char *argv[])
{
  unsigned long pcapng_flags = 0;
  int size, origsize, r, linktype;
  char *buffer;
  struct timeval tm;
  pkt_asm_list_t list;

  argument_read(&argc, argv, args);
  if (nendian) pcapng_flags = PKT_PCAPNG_WRITE_FLAG_ENDIAN_NATIVE;
  if (lendian) pcapng_flags = PKT_PCAPNG_WRITE_FLAG_ENDIAN_LITTLE;
  if (bendian) pcapng_flags = PKT_PCAPNG_WRITE_FLAG_ENDIAN_BIG;

  buffer = malloc(bufsize);
  if (buffer == NULL)
    error_exit("Out of memory.\n");

#ifdef WIN32
  if (!isatty(fileno(stdout)))
    setmode(fileno(stdout), O_BINARY);
#endif

  pkt_pcapng_init(pcapng_flags);

  while (!terminated) {
    list = pkt_asm_list_create();
    size = pkt_text_read(stdin, 0, buffer, bufsize, &linktype, &origsize, &tm,
			 list);
    if (size < 0)
      break;
    if (size == bufsize)
      error_exit("Out of buffer.\n");

    if (linktype == DLT_UNDEFINED)
      linktype = DLT_EN10MB;
    if (lltype != DLT_UNDEFINED)
      linktype = lltype;

    pkt_assemble(list, buffer, size, linktype);
    list = pkt_asm_list_destroy(list);

    if (size > 0) {
      if (((int)buffer[0] & 0xFF) == 0xFF) {
	if (nobroad) continue;
      } else if (buffer[0] & 1) {
	if (nomulti) continue;
      }
    }

    if (pkt_asm_list_filter_args(NULL, argc, argv) == 0) {
      list = pkt_asm_list_create();
      pkt_disasm(list, buffer, size, linktype);
      r = pkt_asm_list_filter_args(list, argc, argv);
      list = pkt_asm_list_destroy(list);
      if (r >= 0) {
	if (filrev) r = !r;
	if (r == 0) continue;
      }
    }

    if (skip > 0) {
      skip--;
      continue;
    }

    list = pkt_asm_list_create();
    pkt_asm_list_read_args(list, argc, argv);
    pkt_assemble(list, buffer, size, linktype);
    list = pkt_asm_list_destroy(list);

    signal(SIGINT , sigint_handler);
    signal(SIGTERM, sigint_handler);
    pkt_pcapng_write(stdout, buffer, size, linktype, origsize, &tm);
    signal(SIGINT , SIG_DFL);
    signal(SIGTERM, SIG_DFL);

    if (limit > 0) {
      if (--limit == 0)
	break;
    }
  }

  fflush(stdout);
  free(buffer);

  return 0;
}
