# CONFIGURE THESE AS NEEDED:
MANPREFIX=/usr/local/share/man/man1
BINDIR=/usr/local/bin

CC=gcc
OBJ= a.out
BINS= ndecode nstrobe ntrace ntraf nlist

all: objs 

netbsd openbsd: 
	make objs DEFINES=-DNETBSD

freebsd:
	make objs DEFINES=-DFREEBSD

osx darwin:
	make objs DEFINES=-DDARWIN

linux solaris:
	make objs

objs: ${BINS}

nstrobe:
	$(CC) -O2 $(DEFINES) $@.c -o $@

ntraf:
	$(CC) -O2 $(DEFINES) -lpcap $@.c -o $@

ndecode:
	$(CC) -O2 $(DEFINES) -lpcap $@.c -o $@

ntrace:
	cp ntrace.pl ntrace && chmod +x ntrace

nlist:
	cp nlist.sh nlist && chmod +x nlist

clean:
	rm -f ${OBJ} ${BINS} ${DEV}

install: install-bin install-man

install-bin:
	for i in $(BINS) ; do \
		cp $$i $(BINDIR); \
	done

install-man:
	for i in $(BINS) ; do \
		cp $$i.1 $(MANPREFIXDIR)/$$i.1; \
	done

uninstall: uninstall-bin uninstall-man

uninstall-bin:
	for i in $(BINS) ; do \
		rm -f ${BINDIR}/$$i; \
	done

uninstall-man:
	for i in $(BINS) ; do \
		rm -f $(MANPREFIXDIR)/$$i.1; \
	done

