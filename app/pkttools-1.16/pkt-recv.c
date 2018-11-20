#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>

#include "defines.h"

#include "argument.h"
#include "asm_val.h"
#include "asm_field.h"
#include "asm_entry.h"
#include "asm_list.h"
#include "assemble.h"
#include "disasm.h"
#include "text.h"
#include "lib.h"

static void help()
{
  fprintf(stderr, "pkt-recv\n");
  fprintf(stderr, "\tReceive packets from network and output to stdout.\n\n");
  fprintf(stderr, "EXAMPLE:\n");
  fprintf(stderr, "\t$ pkt-recv -i eth0\n");
  fprintf(stderr, "\t$ pkt-recv -i eth0 > packet.txt\n\n");
  fprintf(stderr, "OPTIONS:\n");
  fprintf(stderr, "\t-h\t\tOutput help of options.\n");
  fprintf(stderr, "\t-k\t\tOutput help of keys.\n");
  fprintf(stderr, "\t-b <size>\tBuffer size.\n");
  fprintf(stderr, "\t-s <count>\tSkip count.\n");
  fprintf(stderr, "\t-l <count>\tProcessing limit.\n");
  fprintf(stderr, "\t-r\t\tReverse filter rule.\n");
  fprintf(stderr, "\t-nb\t\tSkip broadcast packet.\n");
  fprintf(stderr, "\t-nm\t\tSkip multicast packet.\n");
  fprintf(stderr, "\t-do\t\tOutput data only.\n");
  fprintf(stderr, "\t-lt <type>\tLink-layer type.\n");
  fprintf(stderr, "\t-n <count>\tOutput column.\n");
  fprintf(stderr, "\t-a\t\tOutput field assembly.\n");
  fprintf(stderr, "\t-i <interface>\tNetwork interface.\n");
  fprintf(stderr, "\t-np\t\tNot promiscuous mode.\n");
  fprintf(stderr, "\t-ro\t\tNot receive outgoing packet.\n");
  fprintf(stderr, "\t-so\t\tNot receive incoming packet.\n");
  exit(0);
}

static void help_key()
{
  fprintf(stderr, "FILTER KEYS:\n");
  pkt_asm_field_output_key_list(stderr, "\t");
  exit(0);
}

static char *ifname = NULL;
static int bufsize  = PKT_BUFFER_SIZE_DEFAULT;
static int skip     = 0;
static int limit    = 0;
static int filrev   = ARGUMENT_FLAG_OFF;
static int nobroad  = ARGUMENT_FLAG_OFF;
static int nomulti  = ARGUMENT_FLAG_OFF;
static int dataonly = ARGUMENT_FLAG_OFF;
static int lltype   = DLT_UNDEFINED;
static int column   = 0;
static int asmlist  = ARGUMENT_FLAG_OFF;
static int promisc  = ARGUMENT_FLAG_ON;
static int recvonly = ARGUMENT_FLAG_OFF;
static int sendonly = ARGUMENT_FLAG_OFF;

static Argument args[] = {
  { "-h" , ARGUMENT_TYPE_FUNCTION, help      },
  { "-k" , ARGUMENT_TYPE_FUNCTION, help_key  },
  { "-b" , ARGUMENT_TYPE_INTEGER , &bufsize  },
  { "-s" , ARGUMENT_TYPE_INTEGER , &skip     },
  { "-l" , ARGUMENT_TYPE_INTEGER , &limit    },
  { "-r" , ARGUMENT_TYPE_FLAG_ON , &filrev   },
  { "-nb", ARGUMENT_TYPE_FLAG_ON , &nobroad  },
  { "-nm", ARGUMENT_TYPE_FLAG_ON , &nomulti  },
  { "-do", ARGUMENT_TYPE_FLAG_ON , &dataonly },
  { "-lt", ARGUMENT_TYPE_INTEGER , &lltype   },
  { "-n" , ARGUMENT_TYPE_INTEGER , &column   },
  { "-a" , ARGUMENT_TYPE_FLAG_ON , &asmlist  },
  { "-i" , ARGUMENT_TYPE_STRING  , &ifname   },
  { "-np", ARGUMENT_TYPE_FLAG_OFF, &promisc  },
  { "-ro", ARGUMENT_TYPE_FLAG_ON , &recvonly },
  { "-so", ARGUMENT_TYPE_FLAG_ON , &sendonly },
  { NULL , ARGUMENT_TYPE_NONE    , NULL      },
};

static int terminated = 0;
static void sigint_handler(int value)
{
  terminated = 1;
}

int main(int argc, char *argv[])
{
  pktif_t pktif;
  unsigned long recv_flags = 0;
  unsigned long write_flags = 0;
  int size, origsize, r, linktype;
  char *buffer;
  struct timeval tm;
  pkt_asm_list_t list;

  argument_read(&argc, argv, args);
#ifndef USE_WINPCAP
  if (ifname == NULL)
    error_exit("Unknown interface.\n");
#endif
  if (promisc ) recv_flags  |= PKT_RECV_FLAG_PROMISC;
  if (recvonly) recv_flags  |= PKT_RECV_FLAG_RECVONLY;
  if (sendonly) recv_flags  |= PKT_RECV_FLAG_SENDONLY;
  if (dataonly) write_flags |= PKT_TEXT_WRITE_FLAG_DATAONLY;

  pktif = pkthandler.open_recv(ifname, recv_flags, bufsize ? NULL : &bufsize);

  buffer = malloc(bufsize);
  if (buffer == NULL)
    error_exit("Out of memory.\n");

  while (!terminated) {
    size = pkthandler.recv(pktif, buffer, bufsize, &linktype, &origsize, &tm);
    if (size < 0)
      break;
    if (size == bufsize)
      error_exit("Out of buffer.\n");

    if (linktype == DLT_UNDEFINED)
      linktype = DLT_EN10MB;
    if (lltype != DLT_UNDEFINED)
      linktype = lltype;

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

    if (asmlist) {
      list = pkt_asm_list_create();
      pkt_disasm(list, buffer, size, linktype);
    }

    signal(SIGINT , sigint_handler);
    signal(SIGTERM, sigint_handler);
    pkt_text_write(stdout, write_flags, buffer, size, column, linktype,
		   origsize, &tm, list);
    signal(SIGINT , SIG_DFL);
    signal(SIGTERM, SIG_DFL);

    list = pkt_asm_list_destroy(list);

    if (limit > 0) {
      if (--limit == 0)
	break;
    }
  }

  fflush(stdout);
  free(buffer);

  pkthandler.close(pktif);

  return 0;
}
