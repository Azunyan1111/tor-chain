#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>

#include "defines.h"
#ifdef USE_NETLIB
#include <netlib.h>
#endif

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
  fprintf(stderr, "pkt-send\n");
  fprintf(stderr, "\tInput packets from stdin and send to network.\n\n");
  fprintf(stderr, "EXAMPLE:\n");
  fprintf(stderr, "\t$ pkt-recv -i eth0 | pkt-send -i eth1\n");
  fprintf(stderr, "\t$ cat packet.txt | pkt-send -i eth0\n\n");
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
  fprintf(stderr, "\t-i <interface>\tNetwork interface.\n");
  fprintf(stderr, "\t-w <usec>\tSending interval.\n");
  fprintf(stderr, "\t-c\t\tAuto complete sender MAC address.\n");
  fprintf(stderr, "\t-f\t\tIgnore packet time.\n");
  fprintf(stderr, "\t-j\t\tHave interval from just before packet.\n");
  exit(0);
}

static void help_key()
{
  fprintf(stderr, "FILTER KEYS:\n");
  pkt_asm_field_output_key_list(stderr, "\t");
  exit(0);
}

static char *ifname   = NULL;
static int bufsize    = PKT_BUFFER_SIZE_DEFAULT;
static int skip       = 0;
static int limit      = 0;
static int filrev     = ARGUMENT_FLAG_OFF;
static int nobroad    = ARGUMENT_FLAG_OFF;
static int nomulti    = ARGUMENT_FLAG_OFF;
static int lltype     = DLT_UNDEFINED;
static int waitusec   = 0;
static int complete   = ARGUMENT_FLAG_OFF;
static int interval   = ARGUMENT_FLAG_ON;
static int justbefore = ARGUMENT_FLAG_OFF;

static Argument args[] = {
  { "-h" , ARGUMENT_TYPE_FUNCTION, help        },
  { "-k" , ARGUMENT_TYPE_FUNCTION, help_key    },
  { "-b" , ARGUMENT_TYPE_INTEGER , &bufsize    },
  { "-s" , ARGUMENT_TYPE_INTEGER , &skip       },
  { "-l" , ARGUMENT_TYPE_INTEGER , &limit      },
  { "-r" , ARGUMENT_TYPE_FLAG_ON , &filrev     },
  { "-nb", ARGUMENT_TYPE_FLAG_ON , &nobroad    },
  { "-nm", ARGUMENT_TYPE_FLAG_ON , &nomulti    },
  { "-lt", ARGUMENT_TYPE_INTEGER , &lltype     },
  { "-i" , ARGUMENT_TYPE_STRING  , &ifname     },
  { "-w" , ARGUMENT_TYPE_INTEGER , &waitusec   },
  { "-c" , ARGUMENT_TYPE_FLAG_ON , &complete   },
  { "-f" , ARGUMENT_TYPE_FLAG_OFF, &interval   },
  { "-j" , ARGUMENT_TYPE_FLAG_ON , &justbefore },
  { NULL , ARGUMENT_TYPE_NONE    , NULL        },
};

static int timecmp(struct timeval *t0, struct timeval *t1)
{
  if (t0->tv_sec  > t1->tv_sec ) return  1;
  if (t0->tv_sec  < t1->tv_sec ) return -1;
  if (t0->tv_usec > t1->tv_usec) return  1;
  if (t0->tv_usec < t1->tv_usec) return -1;
  return 0;
}

static int timesub(struct timeval *td, struct timeval *t0, struct timeval *t1)
{
  struct timeval t;
  if (timecmp(t0, t1) < 0)
    return -1;
  t.tv_sec  = t0->tv_sec;
  t.tv_usec = t0->tv_usec;
  while (t.tv_usec < t1->tv_usec) {
    t.tv_sec--;
    t.tv_usec += 1000000;
  }
  td->tv_sec  = t.tv_sec  - t1->tv_sec;
  td->tv_usec = t.tv_usec - t1->tv_usec;
  return 0;
}

static int terminated = 0;
static void sigint_handler(int value)
{
  terminated = 1;
}

int main(int argc, char *argv[])
{
  pktif_t pktif;
  unsigned long send_flags = 0;
  int size, origsize, r, linktype;
  char *buffer;
  struct timeval starttime, firsttime, nowtime, tm, t0, t1;
  pkt_asm_list_t list;
  int first = 1;

  argument_read(&argc, argv, args);
#ifndef USE_WINPCAP
  if (ifname == NULL)
    error_exit("Unknown interface.\n");
#endif
  if (complete) send_flags |= PKT_SEND_FLAG_COMPLETE;
  if (interval) send_flags |= PKT_SEND_FLAG_INTERVAL;

  pktif = pkthandler.open_send(ifname, send_flags);

  buffer = malloc(bufsize);
  if (buffer == NULL)
    error_exit("Out of memory.\n");

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

    if ((send_flags & PKT_SEND_FLAG_INTERVAL) && (tm.tv_sec || tm.tv_usec)) {
      if (first) {
	firsttime.tv_sec  = tm.tv_sec;
	firsttime.tv_usec = tm.tv_usec;
	gettimeofday(&starttime, NULL);
	first = 0;
      } else {
	gettimeofday(&nowtime, NULL);
	if (timesub(&t0, &tm, &firsttime) == 0)
	  if (timesub(&t1, &nowtime, &starttime) == 0)
	    if (timesub(&t0, &t0, &t1) == 0)
	      select(0, NULL, NULL, NULL, &t0);
	if (justbefore) {
	  firsttime.tv_sec  = tm.tv_sec;
	  firsttime.tv_usec = tm.tv_usec;
	  starttime.tv_sec  = nowtime.tv_sec;
	  starttime.tv_usec = nowtime.tv_usec;
	}
      }
    }

    signal(SIGINT , sigint_handler);
    signal(SIGTERM, sigint_handler);
    pkthandler.send(pktif, buffer, size, linktype, origsize, &tm);
    signal(SIGINT , SIG_DFL);
    signal(SIGTERM, SIG_DFL);

    if (limit > 0) {
      if (--limit == 0)
	break;
    }

    if (waitusec > 0)
      usleep(waitusec);
  }

  free(buffer);

  pkthandler.close(pktif);

  return 0;
}
