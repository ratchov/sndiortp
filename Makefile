CFLAGS = -Wall -O2 -g
LIBS = -lsndio
SRCDIR = .

PREFIX = /usr
BINDIR = $(PREFIX)/bin

all:	sndiortp

clean:
	rm -f -- sndiortp.o sndiortp

install:
	mkdir -p $(DESTDIR)$(BINDIR)
	cp sndiortp $(DESTDIR)$(BINDIR)

uninstall:
	rm -- $(DESTDIR)$(BINDIR)

sndiortp: sndiortp.o
	$(CC) $(LDFLAGS) -o sndiortp sndiortp.o $(LIBS)

sndiortp.o: $(SRCDIR)/sndiortp.c
	$(CC) $(CFLAGS) -c $(SRCDIR)/sndiortp.c
