CFLAGS = -Wall -O2
LIBS = -lsndio
SRCDIR = .

all:	sndiortp

clean:
	rm -f -- sndiortp.o sndiortp

sndiortp: sndiortp.o
	$(CC) $(LDLAGS) -o sndiortp sndiortp.o $(LIBS)

sndiortp.o: $(SRCDIR)/sndiortp.c
	$(CC) $(CFLAGS) -c $(SRCDIR)/sndiortp.c
