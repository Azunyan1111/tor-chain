#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "defines.h"

#include "pcap.h"
#include "lib.h"

struct pcap_file_header {
  pkt_uint32 magic;
#define PCAP_FILE_HEADER_MAGIC 0xA1B2C3D4
  pkt_uint16 version_major;
  pkt_uint16 version_minor;
#define PCAP_FILE_HEADER_VERSION_MAJOR 2
#define PCAP_FILE_HEADER_VERSION_MINOR 4
  pkt_int32 thiszone;
  pkt_uint32 sigfigs;
  pkt_uint32 snaplen;
#define PCAP_FILE_HEADER_SNAPLEN 0xFFFF
  pkt_uint32 linktype;
};

struct pcap_packet_header {
  struct {
    pkt_uint32 tv_sec;
    pkt_uint32 tv_usec;
  } ts;
  pkt_uint32 caplen;
  pkt_uint32 len;
};

typedef union {
  pkt_uint32 w;
  pkt_uint16 h[2];
  pkt_uint8  b[4];
} eword_t;

static pkt_uint32 read_ne32(pkt_uint32 val)
{
  return val;
}

static pkt_uint16 read_ne16(pkt_uint16 val)
{
  return val;
}

static pkt_uint32 write_ne32(pkt_uint32 val)
{
  return val;
}

static pkt_uint16 write_ne16(pkt_uint16 val)
{
  return val;
}

static pkt_uint32 read_le32(pkt_uint32 val)
{
  eword_t ew;
  ew.w = val;
  return (ew.b[3] << 24) | (ew.b[2] << 16) | (ew.b[1] << 8) | ew.b[0];
}

static pkt_uint32 read_be32(pkt_uint32 val)
{
  eword_t ew;
  ew.w = val;
  return (ew.b[0] << 24) | (ew.b[1] << 16) | (ew.b[2] << 8) | ew.b[3];
}

static pkt_uint16 read_le16(pkt_uint16 val)
{
  eword_t ew;
  ew.h[0] = val;
  return (ew.b[1] << 8) | ew.b[0];
}

static pkt_uint16 read_be16(pkt_uint16 val)
{
  eword_t ew;
  ew.h[0] = val;
  return (ew.b[0] << 8) | ew.b[1];
}

static pkt_uint32 write_le32(pkt_uint32 val)
{
  eword_t ew;
  ew.b[3] = (val >> 24) & 0xff;
  ew.b[2] = (val >> 16) & 0xff;
  ew.b[1] = (val >>  8) & 0xff;
  ew.b[0] = (val      ) & 0xff;
  return ew.w;
}

static pkt_uint32 write_be32(pkt_uint32 val)
{
  eword_t ew;
  ew.b[0] = (val >> 24) & 0xff;
  ew.b[1] = (val >> 16) & 0xff;
  ew.b[2] = (val >>  8) & 0xff;
  ew.b[3] = (val      ) & 0xff;
  return ew.w;
}

static pkt_uint16 write_le16(pkt_uint16 val)
{
  eword_t ew;
  ew.b[1] = (val >> 8) & 0xff;
  ew.b[0] = (val     ) & 0xff;
  return ew.h[0];
}

static pkt_uint16 write_be16(pkt_uint16 val)
{
  eword_t ew;
  ew.b[0] = (val >> 8) & 0xff;
  ew.b[1] = (val     ) & 0xff;
  return ew.h[0];
}

typedef pkt_uint32 (*convert_32_t)(pkt_uint32 val);
typedef pkt_uint16 (*convert_16_t)(pkt_uint16 val);

static convert_32_t read_32;
static convert_16_t read_16;
static convert_32_t write_32 = write_ne32;
static convert_16_t write_16 = write_ne16;

static int read_file_header(FILE *fp, struct pcap_file_header *filehdr)
{
  if (fread(filehdr, sizeof(*filehdr), 1, fp) == 0)
    return -1;

  if (filehdr->magic == PCAP_FILE_HEADER_MAGIC) {
    read_32 = read_ne32;
    read_16 = read_ne16;
  } else if (read_le32(filehdr->magic) == PCAP_FILE_HEADER_MAGIC) {
    read_32 = read_le32;
    read_16 = read_le16;
  } else if (read_be32(filehdr->magic) == PCAP_FILE_HEADER_MAGIC) {
    read_32 = read_be32;
    read_16 = read_be16;
  } else {
    error_exit("Invalid magic number.\n");
  }

  filehdr->version_major = read_16(filehdr->version_major);
  filehdr->version_minor = read_16(filehdr->version_minor);
  filehdr->thiszone      = read_32(filehdr->thiszone);
  filehdr->sigfigs       = read_32(filehdr->sigfigs);
  filehdr->snaplen       = read_32(filehdr->snaplen);
  filehdr->linktype      = read_32(filehdr->linktype);

  return 0;
}

static int read_packet_header(FILE *fp, struct pcap_packet_header *pkthdr)
{
  if (fread(pkthdr, sizeof(*pkthdr), 1, fp) == 0)
    return -1;

  pkthdr->ts.tv_sec  = read_32(pkthdr->ts.tv_sec);
  pkthdr->ts.tv_usec = read_32(pkthdr->ts.tv_usec);
  pkthdr->caplen     = read_32(pkthdr->caplen);
  pkthdr->len        = read_32(pkthdr->len);

  return 0;
}

static int write_file_header(FILE *fp, int linktype)
{
  struct pcap_file_header filehdr;
  memset(&filehdr, 0, sizeof(filehdr));
  filehdr.magic         = write_32(PCAP_FILE_HEADER_MAGIC);
  filehdr.version_major = write_16(PCAP_FILE_HEADER_VERSION_MAJOR);
  filehdr.version_minor = write_16(PCAP_FILE_HEADER_VERSION_MINOR);
  filehdr.snaplen       = write_32(PCAP_FILE_HEADER_SNAPLEN);
  filehdr.linktype      = write_32(linktype);
  fwrite(&filehdr, sizeof(filehdr), 1, fp);
  return 0;
}

int pkt_pcap_init(unsigned long flags)
{
  switch (flags & PKT_PCAP_WRITE_FLAG_ENDIAN_MASK) {
  case PKT_PCAP_WRITE_FLAG_ENDIAN_LITTLE:
    write_32 = write_le32;
    write_16 = write_le16;
    break;
  case PKT_PCAP_WRITE_FLAG_ENDIAN_BIG:
    write_32 = write_be32;
    write_16 = write_be16;
    break;
  case PKT_PCAP_WRITE_FLAG_ENDIAN_NATIVE:
  default:
    write_32 = write_ne32;
    write_16 = write_ne16;
    break;
  }
  return 0;
}

int pkt_pcap_read(FILE *fp, char *buffer, int size, int *linktypep,
		  int *origsizep, struct timeval *tm)
{
  static int init = 0;
  static struct pcap_file_header filehdr = { 0, 0, 0, 0, 0, 0, DLT_UNDEFINED };
  struct pcap_packet_header pkthdr;
  int capsize;
  pkt_uint32 family;

  if (!init) {
    if (read_file_header(fp, &filehdr) < 0)
      error_exit("Cannot read file header.\n");
    init++;
  }

  if (read_packet_header(fp, &pkthdr) < 0)
    return -1;

  capsize = pkthdr.caplen;
  if (capsize >= size)
    error_exit("Out of buffer.\n");

  if (fread(buffer, capsize, 1, fp) == 0)
    error_exit("Cannot read packet data.\n");

  if (filehdr.linktype == DLT_NULL) {
    if (capsize >= sizeof(family)) {
      memcpy(&family, buffer, sizeof(family));
      family = read_32(family);
      memcpy(buffer, &family, sizeof(family));
    }
  }

  if (linktypep) *linktypep = filehdr.linktype;
  if (origsizep) *origsizep = pkthdr.len;
  if (tm) {
    tm->tv_sec  = pkthdr.ts.tv_sec;
    tm->tv_usec = pkthdr.ts.tv_usec;
  }

  return capsize;
}

int pkt_pcap_write(FILE *fp, char *buffer, int size, int linktype,
		   int origsize, struct timeval *tm)
{
  static int init = 0;
  struct pcap_packet_header pkthdr;
  static int oldlinktype = DLT_UNDEFINED;

  if (linktype == DLT_UNDEFINED)
    linktype = oldlinktype;

  if (!init) {
    write_file_header(fp, linktype);
    oldlinktype = linktype;
    init++;
  }

  if (linktype != oldlinktype)
    error_exit("Link-layer type is changed.\n");

  pkthdr.ts.tv_sec  = write_32(tm->tv_sec);
  pkthdr.ts.tv_usec = write_32(tm->tv_usec);
  pkthdr.caplen     = write_32(size);
  pkthdr.len        = write_32(origsize);

  if (fwrite(&pkthdr, sizeof(pkthdr), 1, fp) == 0)
    return -1;
  if (fwrite(buffer, size, 1, fp) == 0)
    return -1;

  fflush(fp);

  return size;
}
