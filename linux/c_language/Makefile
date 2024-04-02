include Makefile.in

SUBDIRS = \
	pthread \
	signal \
	timer \
	message_queue \
	daemon \
	syslog \
	semaphore \
	terminal \
	va \
	gpio \
	i2c \
	shared_memory \
	mbedtls \
	backtrace \
	ptrace \
	duma \
	memwatch \
	standard/va \
	standard/qsort

.PHONY: all

all:
	$(info compile packages)
	@for dir in $(SUBDIRS); \
	do \
		$(MAKE) -C $$dir EXTRA_CFLAGS=$(EXTRA_CFLAGS) EXTRA_LDFLAGS=$(EXTRA_LDFLAGS) EXTRA_LIBS=$(EXTRA_LIBS); \
	done

.PHONY: strip

strip:
	$(info strip packages)
	@for dir in $(SUBDIRS); \
	do \
		$(MAKE) -C $$dir strip; \
	done

.PHONY: libs

libs:
	$(info make libraries)
	@for dir in $(SUBDIRS); \
	do \
		$(MAKE) -C $$dir libs EXTRA_CFLAGS=$(EXTRA_CFLAGS) EXTRA_LDFLAGS=$(EXTRA_LDFLAGS) EXTRA_LIBS=$(EXTRA_LIBS); \
	done


.PHONY: install

install:
	$(info install packages)
	@for dir in $(SUBDIRS); \
	do \
		$(MAKE) -C $$dir install DESTDIR=$(DESTDIR); \
	done

.PHONY: uninstall

uninstall:
	$(info uninstall packages)
	@for dir in $(SUBDIRS); \
	do \
		$(MAKE) -C $$dir uninstall DESTDIR=$(DESTDIR); \
	done

.PHONY: clean

clean:
	$(info clean packages)
	@for dir in $(SUBDIRS); \
	do \
		$(MAKE) -C $$dir clean; \
	done
	@rm -rf $(INSTALLDIR)
