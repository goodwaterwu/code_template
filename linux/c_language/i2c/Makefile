include ../Makefile.in

SUBDIRS = \
	i2c_smbus

TPDIR = i2c-tools

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
		git clone git://git.kernel.org/pub/scm/utils/i2c-tools/i2c-tools.git -b v4.3; \
	fi

.PHONY: thirdparty

thirdparty: download
	$(info compile third-party packages)
	cd $(TPDIR) && make install DESTDIR=$(CURDIR)/$(TPDIR)/out
	@for dir in $(SUBDIRS); \
	do \
		ln -srf $(TPDIR)/out/usr/local/include $$dir/include; \
		ln -srf $(TPDIR)/out/usr/local/lib $$dir/lib; \
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
