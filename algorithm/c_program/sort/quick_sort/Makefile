CC = $(CROSS_COMPILE)gcc
CPP = $(CROSS_COMPILE)gcc -E
AR = $(CROSS_COMPILE)ar
LD = $(CROSS_COMPILE)ld
NM = $(CROSS_COMPILE)nm
STRIP = $(CROSS_COMPILE)strip

CFLAGS += $(EXTRA_CFLAGS)
LDFLAGS += $(EXTRA_LDFLAGS)
LIBS += $(EXTRA_LIBS)

EXECFILE = quick_sort

OBJS = $(EXECFILE).o

.PHONY: all

all: quick_sort

.PHONY: quick_sort

quick_sort: $(OBJS)
	@$(CC) $(OBJS) $(CFLAGS) $(LDFLAGS) $(LIBS) -o $@
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
	@rm -f $(OBJS) $(EXECFILE)
	$(info package cleaned)
