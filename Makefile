CFLAGS = -Wall -O2 -g
LIBS = -lsndio
SRCDIR = .

PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
MAN1DIR = $(PREFIX)/man/man1

all:	sndiortp

clean:
	rm -f sndiortp.o sndiortp

install:
	mkdir -p $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)$(MAN1DIR)
	cp sndiortp $(DESTDIR)$(BINDIR)
	cp sndiortp.1 $(DESTDIR)$(MAN1DIR)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/sndiortp
	rm -f $(DESTDIR)$(MAN1DIR)/sndiortp.1

sndiortp: sndiortp.o
	$(CC) $(LDFLAGS) -o sndiortp sndiortp.o $(LIBS)

sndiortp.o: $(SRCDIR)/sndiortp.c
	$(CC) $(CFLAGS) -c $(SRCDIR)/sndiortp.c
