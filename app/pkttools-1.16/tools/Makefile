#USE_MINGW = yes

USE_GETHOSTBYNAME = yes
#USE_NETLIB = yes

POSTFIX = $(USE_MINGW:yes=.exe)

TARGETS = \
	tcp-recv tcp-send tcp6-recv tcp6-send \
	udp-recv udp-send udp6-recv udp6-send \
	tcp-reply tcp-request tcp6-reply tcp6-request \
	udp-reply udp-request udp6-reply udp6-request

OBJS := $(TARGETS:=.o)

TARGETS := $(TARGETS:=$(POSTFIX))

NETLIBDIR = ./netlib

NETLIB = $(NETLIBDIR)/lib/libnet.a

LIBS = $(USE_NETLIB:yes=$(NETLIB))

INSTALLDIR = /usr/local
BINDIR = $(INSTALLDIR)/bin

PREFIX = $(USE_MINGW:yes=mingw32-)

LOCAL_CC = $(PREFIX)gcc
LOCAL_AR = $(PREFIX)ar

HANDOVER_CC ?= no
HANDOVER_AR ?= no

CC = $(HANDOVER_CC:no=$(LOCAL_CC))
AR = $(HANDOVER_AR:no=$(LOCAL_AR))

GFLAGS  = -O -Wall
GFLAGS += -g

CFLAGS  =
CFLAGS += $(USE_NETLIB:yes=-DUSE_NETLIB -I$(NETLIBDIR)/include)
CFLAGS += $(USE_MINGW:yes=-DUSE_MINGW)
CFLAGS += $(USE_GETHOSTBYNAME:yes=-DUSE_GETHOSTBYNAME)

LFLAGS  =
LFLAGS += $(USE_NETLIB:yes=-L$(NETLIBDIR)/lib -lnet)
LFLAGS += $(USE_MINGW:yes=-lwsock32 -lws2_32)

.SUFFIXES:
.SUFFIXES: $(POSTFIX) .o .c

all :		$(TARGETS)

.c.o :
		$(CC) $(GFLAGS) $(CFLAGS) $< -c -o $@

$(NETLIB) :
		cd $(NETLIBDIR) ; $(MAKE) USE_MINGW=$(USE_MINGW)

.o$(POSTFIX) :
		$(CC) $< $(GFLAGS) $(LFLAGS) -o $@

$(TARGETS) :	$(OBJS) $(LIBS)

install :	$(TARGETS)
		cp $(TARGETS) $(BINDIR)

uninstall :
		cd $(BINDIR) ; rm -f $(TARGETS)

clean :		clean-tools $(USE_NETLIB:yes=clean-netlib)

clean-tools :
		rm -f $(LIBS) $(OBJS) $(TARGETS)

clean-netlib :
		-$(MAKE) -C $(NETLIBDIR) USE_MINGW=$(USE_MINGW) clean

allclean :	clean-tools clean-netlib
