include ../Makefile.in

SUBDIRS = \
	gpiod_input \
	gpiod_output \
	gpiod_event \
	gpiod_hold

TPDIR = libgpiod

.PHONY: all

all: thirdparty
	$(info compile packages)
	@for dir in $(SUBDIRS); \
	do \
		$(MAKE) -C $$dir; \
	done

.PHONY: download

download:
	$(info download third-party packages)
	@if [ ! -d $(TPDIR) ]; then \
		git clone https://git.kernel.org/pub/scm/libs/libgpiod/libgpiod.git -b v1.6.2; \
	fi


.PHONY: thirdparty

thirdparty: download
	$(info compile third-party packages)
	cd $(TPDIR) && ./autogen.sh && ./configure --prefix=$(CURDIR)/$(TPDIR)/out && make && make install
	@for dir in $(SUBDIRS); \
	do \
		ln -srf $(TPDIR)/out/lib $$dir/lib; \
		ln -srf $(TPDIR)/out/include $$dir/include; \
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
		rm -rf $$dir/include $$dir/lib; \
	done
	@rm -rf $(INSTALLDIR)
	@rm -rf $(TPDIR)
