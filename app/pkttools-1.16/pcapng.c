#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "defines.h"

#include "pcapng.h"
#include "lib.h"

struct pcapng_block {
  pkt_uint32 type;
#define PCAPNG_BLOCK_TYPE_SECTION_HEADER_BLOCK        0x0A0D0D0A
#define PCAPNG_BLOCK_TYPE_INTERFACE_DESCRIPTION_BLOCK 0x00000001
#define PCAPNG_BLOCK_TYPE_SIMPLE_PACKET_BLOCK         0x00000003
#define PCAPNG_BLOCK_TYPE_NAME_RESOLUTION_BLOCK       0x00000004
#define PCAPNG_BLOCK_TYPE_INTERFACE_STATISTICS_BLOCK  0x00000005
#define PCAPNG_BLOCK_TYPE_ENHANCED_PACKET_BLOCK       0x00000006
  pkt_uint32 total_length;
  /* body */
  /* total length */
};

struct pcapng_section_header_block {
  pkt_uint32 magic;
#define PCAPNG_SECTION_HEADER_BLOCK_MAGIC 0x1A2B3C4D
  pkt_uint16 version_major;
  pkt_uint16 version_minor;
#define PCAPNG_SECTION_HEADER_BLOCK_VERSION_MAJOR 1
#define PCAPNG_SECTION_HEADER_BLOCK_VERSION_MINOR 0
  pkt_uint64 section_length;
#define PCAPNG_SECTION_HEADER_BLOCK_SECTION_LENGTH 0xFFFFFFFFFFFFFFFFLL
  /* options */
  /* total length */
};

struct pcapng_interface_description_block {
  pkt_uint16 linktype;
  pkt_uint16 reserve;
  pkt_uint32 snaplen;
#define PCAPNG_INTERFACE_DESCRIPTION_BLOCK_SNAPLEN 0xFFFF
  /* options */
  /* total length */
};

struct pcapng_simple_packet_block {
  pkt_uint32 len;
  /* packet data */
  /* total length */
};

struct pcapng_name_resolution_block {
  /* not supported */
  int dummy;
  /* total length */
};

struct pcapng_interface_statistics_block {
  pkt_uint32 interface_id;
  struct {
    pkt_uint32 high;
    pkt_uint32 low;
  } ts;
  /* options */
  /* total length */
};

struct pcapng_enhanced_packet_block {
  pkt_uint32 interface_id;
#define PCAPNG_ENHANCED_PACKET_BLOCK_INTERFACE_ID 0
  struct {
    pkt_uint32 high;
    pkt_uint32 low;
  } ts;
  pkt_uint32 caplen;
  pkt_uint32 len;
  /* packet data */
  /* options */
  /* total length */
};

typedef union {
  pkt_uint64 llw;
  pkt_uint32 w[2];
  pkt_uint16 h[4];
  pkt_uint8  b[8];
} eword_t;

static pkt_uint64 read_ne64(pkt_uint64 val)
{
  return val;
}

static pkt_uint32 read_ne32(pkt_uint32 val)
{
  return val;
}

static pkt_uint16 read_ne16(pkt_uint16 val)
{
  return val;
}

static pkt_uint64 write_ne64(pkt_uint64 val)
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

static pkt_uint64 read_le64(pkt_uint64 val)
{
  eword_t ew;
  ew.llw = val;
  return
    ((pkt_uint64)ew.b[7] << 56) | ((pkt_uint64)ew.b[6] << 48) |
    ((pkt_uint64)ew.b[5] << 40) | ((pkt_uint64)ew.b[4] << 32) |
    ((pkt_uint64)ew.b[3] << 24) | ((pkt_uint64)ew.b[2] << 16) |
    ((pkt_uint64)ew.b[1] <<  8) |  (pkt_uint64)ew.b[0];
}

static pkt_uint64 read_be64(pkt_uint64 val)
{
  eword_t ew;
  ew.llw = val;
  return
    ((pkt_uint64)ew.b[0] << 56) | ((pkt_uint64)ew.b[1] << 48) |
    ((pkt_uint64)ew.b[2] << 40) | ((pkt_uint64)ew.b[3] << 32) |
    ((pkt_uint64)ew.b[4] << 24) | ((pkt_uint64)ew.b[5] << 16) |
    ((pkt_uint64)ew.b[6] <<  8) |  (pkt_uint64)ew.b[7];
}

static pkt_uint32 read_le32(pkt_uint32 val)
{
  eword_t ew;
  ew.w[0] = val;
  return (ew.b[3] << 24) | (ew.b[2] << 16) | (ew.b[1] << 8) | ew.b[0];
}

static pkt_uint32 read_be32(pkt_uint32 val)
{
  eword_t ew;
  ew.w[0] = val;
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

static pkt_uint64 write_le64(pkt_uint64 val)
{
  eword_t ew;
  ew.b[7] = (val >> 56) & 0xff;
  ew.b[6] = (val >> 48) & 0xff;
  ew.b[5] = (val >> 40) & 0xff;
  ew.b[4] = (val >> 32) & 0xff;
  ew.b[3] = (val >> 24) & 0xff;
  ew.b[2] = (val >> 16) & 0xff;
  ew.b[1] = (val >>  8) & 0xff;
  ew.b[0] = (val      ) & 0xff;
  return ew.llw;
}

static pkt_uint64 write_be64(pkt_uint64 val)
{
  eword_t ew;
  ew.b[0] = (val >> 56) & 0xff;
  ew.b[1] = (val >> 48) & 0xff;
  ew.b[2] = (val >> 40) & 0xff;
  ew.b[3] = (val >> 32) & 0xff;
  ew.b[4] = (val >> 24) & 0xff;
  ew.b[5] = (val >> 16) & 0xff;
  ew.b[6] = (val >>  8) & 0xff;
  ew.b[7] = (val      ) & 0xff;
  return ew.llw;
}

static pkt_uint32 write_le32(pkt_uint32 val)
{
  eword_t ew;
  ew.b[3] = (val >> 24) & 0xff;
  ew.b[2] = (val >> 16) & 0xff;
  ew.b[1] = (val >>  8) & 0xff;
  ew.b[0] = (val      ) & 0xff;
  return ew.w[0];
}

static pkt_uint32 write_be32(pkt_uint32 val)
{
  eword_t ew;
  ew.b[0] = (val >> 24) & 0xff;
  ew.b[1] = (val >> 16) & 0xff;
  ew.b[2] = (val >>  8) & 0xff;
  ew.b[3] = (val      ) & 0xff;
  return ew.w[0];
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

typedef pkt_uint64 (*convert_64_t)(pkt_uint64 val);
typedef pkt_uint32 (*convert_32_t)(pkt_uint32 val);
typedef pkt_uint16 (*convert_16_t)(pkt_uint16 val);

static convert_64_t read_64;
static convert_32_t read_32;
static convert_16_t read_16;
static convert_64_t write_64 = write_ne64;
static convert_32_t write_32 = write_ne32;
static convert_16_t write_16 = write_ne16;

static int read_dummy(FILE *fp, int size)
{
  char c;
  for (; size > 0; size--) {
    if (fread(&c, 1, 1, fp) == 0)
      error_exit("Cannot read remained area.\n");
  }
  return 0;
}

static int write_dummy(FILE *fp, int size)
{
  char c = 0;
  for (; size > 0; size--) {
    fwrite(&c, 1, 1, fp);
  }
  return 0;
}

static int read_section_header_block(FILE *fp,
				     struct pcapng_section_header_block *shb)
{
  if (fread(shb, sizeof(*shb), 1, fp) == 0)
    error_exit("Cannot read section header block.\n");

  if (shb->magic == PCAPNG_SECTION_HEADER_BLOCK_MAGIC) {
    read_64 = read_ne64;
    read_32 = read_ne32;
    read_16 = read_ne16;
  } else if (read_le32(shb->magic) == PCAPNG_SECTION_HEADER_BLOCK_MAGIC) {
    read_64 = read_le64;
    read_32 = read_le32;
    read_16 = read_le16;
  } else if (read_be32(shb->magic) == PCAPNG_SECTION_HEADER_BLOCK_MAGIC) {
    read_64 = read_be64;
    read_32 = read_be32;
    read_16 = read_be16;
  } else {
    error_exit("Invalid magic number.\n");
  }

  shb->version_major  = read_16(shb->version_major);
  shb->version_minor  = read_16(shb->version_minor);
  shb->section_length = read_64(shb->section_length);

  return sizeof(*shb);
}

static int read_interface_description_block(FILE *fp,
				struct pcapng_interface_description_block *idb)
{
  if (fread(idb, sizeof(*idb), 1, fp) == 0)
    error_exit("Cannot read interface description block.\n");

  idb->linktype = read_16(idb->linktype);
  idb->snaplen  = read_32(idb->snaplen);

  return sizeof(*idb);
}

static int read_simple_packet_block(FILE *fp,
				    struct pcapng_simple_packet_block *spb)
{
  if (fread(spb, sizeof(*spb), 1, fp) == 0)
    error_exit("Cannot read simple packet block.\n");

  spb->len = read_32(spb->len);

  return sizeof(*spb);
}

static int read_name_resolution_block(FILE *fp,
				      struct pcapng_name_resolution_block *nrb)
{
  if (fread(nrb, sizeof(*nrb), 1, fp) == 0)
    error_exit("Cannot read name resolution block.\n");

  /* not supported */

  return sizeof(*nrb);
}

static int read_interface_statistics_block(FILE *fp,
				struct pcapng_interface_statistics_block *isb)
{
  if (fread(isb, sizeof(*isb), 1, fp) == 0)
    error_exit("Cannot read interface statistics block.\n");

  isb->interface_id = read_32(isb->interface_id);
  isb->ts.high      = read_32(isb->ts.high);
  isb->ts.low       = read_32(isb->ts.low);

  return sizeof(*isb);
}

static int read_enhanced_packet_block(FILE *fp,
				      struct pcapng_enhanced_packet_block *epb)
{
  if (fread(epb, sizeof(*epb), 1, fp) == 0)
    error_exit("Cannot read enhanced packet block.\n");

  epb->interface_id = read_32(epb->interface_id);
  epb->ts.high      = read_32(epb->ts.high);
  epb->ts.low       = read_32(epb->ts.low);
  epb->caplen       = read_32(epb->caplen);
  epb->len          = read_32(epb->len);

  return sizeof(*epb);
}

static int read_block(FILE *fp, struct pcapng_block *block,
		      struct pcapng_section_header_block *shb)
{
  int r = 0;

  if (fread(block, sizeof(*block), 1, fp) == 0)
    return -1;

  if (block->type == PCAPNG_BLOCK_TYPE_SECTION_HEADER_BLOCK) {
    r = read_section_header_block(fp, shb);
  }

  if (!shb->magic)
    error_exit("Cannot find section header block.\n");

  block->type         = read_32(block->type);
  block->total_length = read_32(block->total_length);

  return sizeof(*block) + r;
}

static int read_packet(FILE *fp, char *buffer, int size, int capsize)
{
  if (capsize >= size)
    error_exit("Out of buffer.\n");
  if (fread(buffer, capsize, 1, fp) == 0)
    error_exit("Cannot read packet data.\n");
  return capsize;
}

static int write_block(FILE *fp, int type, void *p, int size,
		       void *optp, int optsize)
{
  struct pcapng_block block;
  int total_length;
  int aligned_optsize = ((optsize + 3) / 4) * 4;
  total_length =
    sizeof(block) + size + aligned_optsize + sizeof(block.total_length);
  memset(&block, 0, sizeof(block));
  block.type         = write_32(type);
  block.total_length = write_32(total_length);
  fwrite(&block, sizeof(block), 1, fp);
  fwrite(p, size, 1, fp);
  if (optp) {
    fwrite(optp, optsize, 1, fp);
    write_dummy(fp, aligned_optsize - optsize);
  }
  fwrite(&block.total_length, sizeof(block.total_length), 1, fp);
  return total_length;
}

static int write_section_header_block(FILE *fp)
{
  struct pcapng_section_header_block shb;
  memset(&shb, 0, sizeof(shb));
  shb.magic          = write_32(PCAPNG_SECTION_HEADER_BLOCK_MAGIC);
  shb.version_major  = write_16(PCAPNG_SECTION_HEADER_BLOCK_VERSION_MAJOR);
  shb.version_minor  = write_16(PCAPNG_SECTION_HEADER_BLOCK_VERSION_MINOR);
  shb.section_length = write_64(PCAPNG_SECTION_HEADER_BLOCK_SECTION_LENGTH);
  return write_block(fp, PCAPNG_BLOCK_TYPE_SECTION_HEADER_BLOCK,
		     &shb, sizeof(shb), NULL, 0);
}

static int write_interface_description_block(FILE *fp, int linktype)
{
  struct pcapng_interface_description_block idb;
  memset(&idb, 0, sizeof(idb));
  idb.linktype = write_16(linktype);
  idb.snaplen  = write_32(PCAPNG_INTERFACE_DESCRIPTION_BLOCK_SNAPLEN);
  return write_block(fp, PCAPNG_BLOCK_TYPE_INTERFACE_DESCRIPTION_BLOCK,
		     &idb, sizeof(idb), NULL, 0);
}

int pkt_pcapng_init(unsigned long flags)
{
  switch (flags & PKT_PCAPNG_WRITE_FLAG_ENDIAN_MASK) {
  case PKT_PCAPNG_WRITE_FLAG_ENDIAN_LITTLE:
    write_64 = write_le64;
    write_32 = write_le32;
    write_16 = write_le16;
    break;
  case PKT_PCAPNG_WRITE_FLAG_ENDIAN_BIG:
    write_64 = write_be64;
    write_32 = write_be32;
    write_16 = write_be16;
    break;
  case PKT_PCAPNG_WRITE_FLAG_ENDIAN_NATIVE:
  default:
    write_64 = write_ne64;
    write_32 = write_ne32;
    write_16 = write_ne16;
    break;
  }
  return 0;
}

int pkt_pcapng_read(FILE *fp, char *buffer, int size, int *linktypep,
		    int *origsizep, struct timeval *tm)
{
  struct pcapng_block block;
  static struct pcapng_section_header_block shb = { 0, 0, 0, 0 };
  static struct pcapng_interface_description_block idb = { DLT_UNDEFINED, 0, 0 };
  struct pcapng_simple_packet_block spb;
  struct pcapng_name_resolution_block nrb;
  struct pcapng_interface_statistics_block isb;
  struct pcapng_enhanced_packet_block epb;
  int r, capsize = 0, origsize = 0, finished = 0;
  pkt_uint64 timestamp;
  pkt_uint32 family;

  while (!finished) {
    r = read_block(fp, &block, &shb);

    if (!shb.magic)
      error_exit("Invalid format.\n");

    if (r < 0)
      return -1;

    switch (block.type) {
    case PCAPNG_BLOCK_TYPE_SECTION_HEADER_BLOCK:
      break;
    case PCAPNG_BLOCK_TYPE_INTERFACE_DESCRIPTION_BLOCK:
      r += read_interface_description_block(fp, &idb);
      break;
    case PCAPNG_BLOCK_TYPE_SIMPLE_PACKET_BLOCK:
      r += read_simple_packet_block(fp, &spb);
      capsize = read_packet(fp, buffer, size, spb.len);
      r += capsize;
      origsize = spb.len;
      if (tm) {
	gettimeofday(tm, NULL);
      }
      finished = 1;
      break;
    case PCAPNG_BLOCK_TYPE_NAME_RESOLUTION_BLOCK:
      r += read_name_resolution_block(fp, &nrb);
      break;
    case PCAPNG_BLOCK_TYPE_INTERFACE_STATISTICS_BLOCK:
      r += read_interface_statistics_block(fp, &isb);
      break;
    case PCAPNG_BLOCK_TYPE_ENHANCED_PACKET_BLOCK:
      r += read_enhanced_packet_block(fp, &epb);
      capsize = read_packet(fp, buffer, size, epb.caplen);
      r += capsize;
      origsize = epb.len;
      if (tm) {
	timestamp = ((pkt_uint64)epb.ts.high << 32) | epb.ts.low;
	tm->tv_sec  = timestamp / 1000000;
	tm->tv_usec = timestamp % 1000000;
      }
      finished = 1;
      break;
    default:
      error_exit("Unknown block type.\n");
      break;
    }

    read_dummy(fp, block.total_length - r);
  }

  if (idb.linktype == DLT_NULL) {
    if (capsize >= sizeof(family)) {
      memcpy(&family, buffer, sizeof(family));
      family = read_32(family);
      memcpy(buffer, &family, sizeof(family));
    }
  }

  if (linktypep) *linktypep = idb.linktype;
  if (origsizep) *origsizep = origsize;

  return capsize;
}

int pkt_pcapng_write(FILE *fp, char *buffer, int size, int linktype,
		     int origsize, struct timeval *tm)
{
  static int init = 0;
  struct pcapng_enhanced_packet_block epb;
  pkt_uint64 timestamp;
  static int oldlinktype = DLT_UNDEFINED;
  static int interface_id = PCAPNG_ENHANCED_PACKET_BLOCK_INTERFACE_ID - 1;

  if (linktype == DLT_UNDEFINED)
    linktype = oldlinktype;

  if (!init) {
    write_section_header_block(fp);
    init++;
  }

  if (linktype != oldlinktype) {
    write_interface_description_block(fp, linktype);
    oldlinktype = linktype;
    interface_id++;
  }

  timestamp = ((pkt_uint64)tm->tv_sec * 1000000) + tm->tv_usec;

  memset(&epb, 0, sizeof(epb));
  epb.interface_id = write_32(interface_id);
  epb.ts.high      = write_32((timestamp >> 32) & 0xFFFFFFFF);
  epb.ts.low       = write_32(timestamp & 0xFFFFFFFF);
  epb.caplen       = write_32(size);
  epb.len          = write_32(origsize);

  write_block(fp, PCAPNG_BLOCK_TYPE_ENHANCED_PACKET_BLOCK,
	      &epb, sizeof(epb), buffer, size);

  fflush(fp);

  return size;
}
