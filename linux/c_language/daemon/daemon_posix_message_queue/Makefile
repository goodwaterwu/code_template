CC = $(CROSS_COMPILE)gcc
CPP = $(CROSS_COMPILE)gcc -E
AR = $(CROSS_COMPILE)ar
LD = $(CROSS_COMPILE)ld
NM = $(CROSS_COMPILE)nm
STRIP = $(CROSS_COMPILE)strip

CFLAGS += $(EXTRA_CFLAGS)
LDFLAGS += $(EXTRA_LDFLAGS)
LIBS += $(EXTRA_LIBS)

SENDFILE = posix_message_queue_notify_signal_client
RECVFILE = posix_message_queue_notify_signal_server

EXECFILE = \
	   $(SENDFILE) \
	   $(RECVFILE)

SEND_OBJS = $(SENDFILE).o
RECV_OBJS = $(RECVFILE).o

.PHONY: all

all: posix_message_queue_notify_signal_client posix_message_queue_notify_signal_server

.PHONY: posix_message_queue_notify_signal_client

posix_message_queue_notify_signal_client: $(SEND_OBJS)
	@$(CC) $(SEND_OBJS) $(CFLAGS) $(LDFLAGS) $(LIBS) -o $@
	$(info package compiled)

.PHONY: posix_message_queue_notify_signal_server

posix_message_queue_notify_signal_server: $(RECV_OBJS)
	@$(CC) $(RECV_OBJS) $(CFLAGS) $(LDFLAGS) $(LIBS) -o $@
	$(info package compiled)

%.o: %.c
	$(CC) -c $< $(CFLAGS) $(LDFLAGS) $(LIBS) -o $@

.PHONY: strip

strip:

.PHONY: libs

libs:

.PHONY: install

install:
	$(shell echo $(DESTDIR) > .install)
	install -d $(DESTDIR)/usr/local/sbin
	install -m 755 $(EXECFILE) $(DESTDIR)/usr/local/sbin
	$(info package installed)

.PHONY: uninstall

uninstall:
	$(eval DESTDIR := $(shell cat .install))
	@for f in $(EXECFILE); \
	do \
		@rm -f $(DESTDIR)/usr/local/sbin/$$f; \
	done
	rm -f .install
	$(info package uninstalled)

.PHONY: clean

clean:
	@rm -f $(SEND_OBJS) $(RECV_OBJS) $(EXECFILE)
	$(info package cleaned)
