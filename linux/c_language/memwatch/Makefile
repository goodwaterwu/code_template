include ../Makefile.in

SUBDIRS = \
	detect_memory_leak \
	detect_overflow \
	detect_underflow

.PHONY: all

all: download
	$(info compile packages)
	@for dir in $(SUBDIRS); \
	do \
		$(MAKE) -C $$dir; \
	done

.PHONY: download

download:
	$(info download third-party packages)
	wget -c https://github.com/linkdata/memwatch/archive/refs/tags/v2.71.tar.gz -O memwatch-2.71.tar.gz
	tar -zxvf memwatch-2.71.tar.gz
	@for dir in $(SUBDIRS); \
	do \
		ln -srf memwatch-2.71/memwatch.c $$dir/memwatch.c; \
		ln -srf memwatch-2.71/memwatch.h $$dir/memwatch.h; \
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
		$(MAKE) -C $$dir libs; \
	done


.PHONY: install

install:
	$(info install packages)
	@for dir in $(SUBDIRS); \
	do \
		$(MAKE) -C $$dir install; \
	done

.PHONY: uninstall

uninstall:
	$(info uninstall packages)
	@for dir in $(SUBDIRS); \
	do \
		$(MAKE) -C $$dir uninstall; \
	done

.PHONY: clean

clean:
	$(info clean packages)
	@for dir in $(SUBDIRS); \
	do \
		$(MAKE) -C $$dir clean; \
		rm -rf $$dir/memwatch.[ch]; \
	done
	@rm -rf $(INSTALLDIR)
	@rm -rf memwatch-2.71 memwatch-2.71.tar.gz
