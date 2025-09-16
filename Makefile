SRCDIR = .

INCLUDE =	# extra -I
DEFS =		# extra -D
LIB =		# extra -L and -l

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
	cp $(SRCDIR)/sndiortp.1 $(DESTDIR)$(MAN1DIR)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/sndiortp
	rm -f $(DESTDIR)$(MAN1DIR)/sndiortp.1

sndiortp: sndiortp.o
	$(CC) $(LDFLAGS) -o sndiortp sndiortp.o -lsndio $(LIB)

sndiortp.o: $(SRCDIR)/sndiortp.c
	$(CC) $(CFLAGS) $(DEFS) $(INCLUDE) -c $(SRCDIR)/sndiortp.c
