include ../Makefile.in

SUBDIRS = \
	bubble_sort \
	selection_sort \
	insertion_sort \
	merge_sort \
	quick_sort

.PHONY: all

all:
	$(info compile packages)
	@for dir in $(SUBDIRS); \
	do \
		$(MAKE) -C $$dir; \
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
	done
	@rm -rf $(INSTALLDIR)
