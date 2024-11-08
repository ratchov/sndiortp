#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <sndio.h>

#define RTP_MTU			(1500 - 8 - 12)
#define RTP_MAXDATA		(RTP_MTU - 20)
#define RTP_DEFAULT_PORT	"5004"
#define RTP_MAXSRC		64

struct rtp_hdr {
#define RTP_VERSION		14
#define RTP_VERSION_MASK	0x3
#define RTP_PADDING		13
#define RTP_EXTENSION		12
#define RTP_CSRC_COUNT		8
#define RTP_CSRC_COUNT_MASK	0xf
#define RTP_MARKER		7
#define RTP_PAYLOAD		0
#define RTP_PAYLOAD_MASK	0x7f
	uint16_t flags;
	uint16_t seq;
	uint32_t ts;
	uint32_t ssrc;
};

struct rtp {
	int fd;
	struct rtp_src {
		struct rtp_src *next;
		unsigned int seq, ts, ssrc;
		unsigned int nch, bps;
		int started;

		int *buf;
		size_t buf_start, buf_used, buf_len;
	} *src_list, *src_freelist;

	struct rtp_dst {
		struct rtp_dst *next;
		struct sockaddr_storage sa;
		socklen_t salen;
		unsigned int seq, ts, ssrc;
	} *dst_list;

	int rate;
};

int verbose;

unsigned char *play_buf;
size_t play_size, play_start, play_end;
unsigned int play_nch;

int *rec_buf;
size_t rec_size, rec_start, rec_end;
unsigned int rec_nch;

unsigned int rtp_bufsz;
unsigned int rtp_bps;
unsigned int rtp_nch;

long long rtp_time;

struct rtp_src *
rtp_mksrc(struct rtp *rtp, unsigned int ssrc, unsigned int seq, unsigned int ts)
{
	struct rtp_src *src, **psrc;

	psrc = &rtp->src_list;
	while (1) {
		src = *psrc;
		if (src == NULL) {
			src = rtp->src_freelist;
			if (src == NULL) {
				fprintf(stderr, "out of free src structures\n");
				exit(1);
			}
			rtp->src_freelist = src->next;

			src->ssrc = ssrc;
			src->seq = seq;
			src->ts = ts;
			src->started = 0;
			src->buf_start = src->buf_used = 0;
			src->next = NULL;
			src->nch = rtp_nch;
			src->bps = rtp_bps;
			*psrc = src;
			if (verbose)
				fprintf(stderr, "ssrc 0x%x: created\n", src->ssrc);
			return src;
		}
		if (src->ssrc == ssrc)
			break;
		psrc = &src->next;
	}

	if (seq != src->seq) {
		if (verbose)
			fprintf(stderr, "ssrc 0x%x: %u: bad seq number (expected %u)\n",
			    src->ssrc, seq, src->seq);
		goto err_drop;
	}

	if (ts != src->ts) {
		if (verbose)
			fprintf(stderr, "ssrc 0x%x: %u: bad time-stamp (expected %u)\n",
			    src->ssrc, ts, src->ts);
		goto err_drop;
	}

	return src;

err_drop:
	*psrc = src->next;
	src->next = rtp->src_freelist;
	rtp->src_freelist = src;
	return NULL;
}

int
rtp_mkdst(struct rtp *rtp, const char *host, const char *serv)
{
	struct rtp_dst *dst;
	struct addrinfo *ailist, *ai, aihints;
	int error;

	memset(&aihints, 0, sizeof(struct addrinfo));
	aihints.ai_family = AF_INET;
	aihints.ai_socktype = SOCK_DGRAM;
	aihints.ai_protocol = IPPROTO_UDP;
	error = getaddrinfo(host, serv, &aihints, &ailist);
	if (error) {
		fprintf(stderr, "getaddrinfo: %s: %s\n", host, gai_strerror(error));
		exit(1);
	}

	ai = ailist;
	if (ai == NULL) {
		fprintf(stderr, "getaddrinfo: %s: no IP address\n", host);
		exit(1);
	}

	dst = malloc(sizeof(struct rtp_dst));
	if (dst == NULL) {
		perror("dst");
		exit(1);
	}

	memcpy(&dst->sa, ai->ai_addr, ai->ai_addrlen);
	dst->salen = ai->ai_addrlen;
	dst->seq = arc4random();
	dst->ts = arc4random();
	dst->ssrc = arc4random();

	dst->next = rtp->dst_list;
	rtp->dst_list = dst;

	freeaddrinfo(ai);
	return 1;
}

int
rtp_recvpkt(struct rtp *rtp)
{
	union {
		struct rtp_hdr hdr;
		unsigned char buf[RTP_MTU];
	} u;
	unsigned char *data;
	struct rtp_src *src;
	struct msghdr msg;
	struct iovec iov[1];
	unsigned int flags, seq, ts, ssrc, ncsrc, version, type;
	uint32_t hdrext;
	ssize_t size;
	size_t offs, nsamp, end, avail, count, i, j;
	int s, *p;

	iov[0].iov_base = u.buf;
	iov[0].iov_len = RTP_MTU;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	size = recvmsg(rtp->fd, &msg, MSG_DONTWAIT);
	if (size == -1) {
		if (errno == EAGAIN)
			return 0;
		fprintf(stderr, "recvmsg: %s\n", strerror(errno));
		exit(1);
	}

	if (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
		fprintf(stderr, "recvmsg: truncated\n");
		exit(1);
	}

	if (size < sizeof(struct rtp_hdr)) {
		fprintf(stderr, "%zd: pkt size too short\n", size);
		exit(1);
	}

	flags = ntohs(u.hdr.flags);
	seq = ntohs(u.hdr.seq);
	ts = ntohl(u.hdr.ts);
	ssrc = ntohl(u.hdr.ssrc);

	ncsrc = (flags >> RTP_CSRC_COUNT) & RTP_CSRC_COUNT_MASK;
	version = (flags >> RTP_VERSION) & RTP_VERSION_MASK;
	type = (flags >> RTP_PAYLOAD) & RTP_PAYLOAD_MASK;

	offs = sizeof(struct rtp_hdr) + 4 * ncsrc;

	if (version != 2) {
		fprintf(stderr, "%d: unsupported version\n", version);
		exit(1);
	}

	if (type != 96) {
		fprintf(stderr, "%d: unexpected payload type\n", type);
		exit(1);
	}

	if (flags & (1 << RTP_PADDING)) {
		fprintf(stderr, "rtp padding not supported\n");
		exit(1);
	}

	if (flags & (1 << RTP_EXTENSION)) {
		hdrext = ntohl(*(uint32_t *)(u.buf + offs));
		offs += 4 * (hdrext & 0xffff);
	}

	src = rtp_mksrc(rtp, ssrc, seq, ts);
	if (src == NULL)
		return 1;

	data = u.buf + offs;
	nsamp = (size - offs) / (src->bps * src->nch);

	src->ts += nsamp;
	src->seq = (src->seq + 1) & 0xffff;

	while (nsamp > 0) {

		if (src->buf_used >= src->buf_len) {
			fprintf(stderr, "ssrc 0x%x: overflow\n", src->ssrc);
			exit(1);
		}

		end = src->buf_start + src->buf_used;
		if (end >= src->buf_len)
			end -= src->buf_len;
		avail = src->buf_len - src->buf_used;
		count = src->buf_len - end;
		if (count > avail)
			count = avail;
		if (count > nsamp)
			count = nsamp;
		p = src->buf + end * src->nch;

		for (i = count; i > 0; i--) {
			for (j = src->nch; j > 0; j--) {
				s = data[0] << 24 | data[1] << 16;
				if (src->bps == 3)
					s |= data[2] << 8;
				data += src->bps;
				(*p++) = s;
			}
		}

		nsamp -= count;
		src->buf_used += count;
	}

	return 1;
}

void
rtp_sendpkt(struct rtp *rtp, void *data, unsigned int count)
{
	struct rtp_dst *dst;
	struct rtp_hdr hdr;
	struct msghdr msg;
	struct iovec iov[2];
	size_t size;
	ssize_t n;

	for (dst = rtp->dst_list; dst != NULL; dst = dst->next) {

		size = count * rtp_bps * rtp_nch;

		hdr.flags = htons(2 << RTP_VERSION | 96 << RTP_PAYLOAD);
		hdr.seq = htons(dst->seq);
		hdr.ts = htonl(dst->ts);
		hdr.ssrc = htonl(dst->ssrc);

		dst->seq++;
		dst->ts += count;

		iov[0].iov_base = &hdr;
		iov[0].iov_len = sizeof(struct rtp_hdr);
		iov[1].iov_base = data;
		iov[1].iov_len = size;

		memset(&msg, 0, sizeof(msg));
		msg.msg_name = &dst->sa;
		msg.msg_namelen = dst->salen;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_iov = iov;
		msg.msg_iovlen = 2;

		n = sendmsg(rtp->fd, &msg, 0);
		if (n == -1) {
			fprintf(stderr, "sendmsg: %s\n", strerror(errno));
			exit(1);
		}
		if (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
			fprintf(stderr, "sendmsg: truncated\n");
			exit(1);
		}
	}

	if (verbose >= 2)
		fprintf(stderr, "sent %d samples\n", count);
}

void
rtp_sendblk(struct rtp *rtp, unsigned char *data, unsigned int blksz)
{
	unsigned int npkt, pktsz, nsamp, maxsamp;
	unsigned int bpf;

	bpf = rtp_bps * rtp_nch;
	maxsamp = RTP_MAXDATA / bpf;
	npkt = (blksz + maxsamp - 1) / maxsamp;

	if (verbose >= 2)
		fprintf(stderr, "sending %d bytes (%d pkts)\n", blksz * bpf, npkt);

	pktsz = (blksz + npkt - 1) / npkt;
	nsamp = blksz;
	while (nsamp > 0) {
		if (pktsz > nsamp)
			pktsz = nsamp;
		rtp_sendpkt(rtp, data, pktsz);
		nsamp -= pktsz;
		data += pktsz * bpf;
	}
}

int
rtp_mixsrc(struct rtp_src *src, void *mixbuf, size_t todo)
{
	size_t count, i, j;
	long long s;
	int *p, *q;

	if (!src->started) {
		if (src->buf_used < rtp_bufsz)
			return 1;
		if (verbose >= 2)
			fprintf(stderr, "ssrc 0x%x: started\n", src->ssrc);
		src->started = 1;
	}

	p = mixbuf;

	while (todo > 0) {
		if (src->buf_used == 0) {
			if (verbose)
				fprintf(stderr, "ssrc 0x%x: stopped\n", src->ssrc);
			return 0;
		}

		count = src->buf_len - src->buf_start;
		if (count > src->buf_used)
			count = src->buf_used;
		if (count > todo)
			count = todo;
		q = src->buf + src->buf_start * src->nch;

		for (i = count; i > 0; i--) {
			for (j = src->nch; j > 0; j--) {
				s = *p + *q;
				if (s > INT_MAX)
					s = INT_MAX;
				if (s < -INT_MAX)
					s = -INT_MAX;
				*p = s;
				p++;
				q++;
			}
			p += play_nch - src->nch;
		}

		src->buf_used -= count;
		src->buf_start += count;
		if (src->buf_start >= src->buf_len)
			src->buf_start -= src->buf_len;

		todo -= count;
	}
	return 1;
}

void
rtp_mixbuf(struct rtp *rtp, void *mixbuf, size_t count)
{
	struct rtp_src *src, **psrc;

	memset(mixbuf, 0, count * play_nch * sizeof(int));

	psrc = &rtp->src_list;
	while ((src = *psrc) != NULL) {
		if (rtp_mixsrc(src, mixbuf, count))
			psrc = &src->next;
		else {
			*psrc = src->next;
			free(src);
		}
	}
}

int
rtp_init(struct rtp *rtp, const char *host, const char *serv, int listen)
{
	struct addrinfo *ailist, *ai, aihints;
	int fd, tos, error;

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd == -1) {
		fprintf(stderr, "socket: %s\n", strerror(errno));
		exit(1);
	}

	tos = IPTOS_LOWDELAY;
	if (setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) == -1) {
		fprintf(stderr, "setsockopt: IP_TOS: %s\n", strerror(errno));
		exit(1);
	}

	if (listen) {
		memset(&aihints, 0, sizeof(struct addrinfo));
		aihints.ai_family = AF_INET;
		aihints.ai_socktype = SOCK_DGRAM;
		aihints.ai_protocol = IPPROTO_UDP;
		error = getaddrinfo(host, serv, &aihints, &ailist);
		if (error) {
			fprintf(stderr, "getaddrinfo: %s: %s\n", host, gai_strerror(error));
			exit(1);
		}

		ai = ailist;
		if (ai == NULL) {
			fprintf(stderr, "getaddrinfo: %s: no IP address\n", host);
			exit(1);
		}

		if (bind(fd, ai->ai_addr, ai->ai_addrlen) == -1) {
			fprintf(stderr, "bind: %s\n", strerror(errno));
			exit(1);
		}
		freeaddrinfo(ai);
	}

	rtp->fd = fd;
	rtp->src_list = rtp->src_freelist = NULL;
	rtp->dst_list = NULL;

	return 1;
}

void
rtp_loop(struct rtp *rtp, const char *dev, unsigned int rate, int listen)
{
	struct rtp_src *src;
	struct timespec ts;
	unsigned char *data, *p;
	struct pollfd *pfds;
	struct sio_hdl *hdl;
	struct sio_par par;
	size_t nfds;
	int events, n;
	unsigned int mode;
	int s, *q;
	int i, c;

	mode = 0;
	if (listen)
		mode |= SIO_PLAY;
	if (rtp->dst_list)
		mode |= SIO_REC;

	hdl = sio_open(dev, mode, 1);
	if (hdl == NULL) {
		fprintf(stderr, "%s: failed to open audio device\n", dev);
		return;
	}

	pfds = malloc((sio_nfds(hdl) + 1) * sizeof(struct pollfd));
	if (pfds == NULL) {
		perror("pfds");
		exit(1);
	}

	sio_initpar(&par);
	par.round = rate / 1000;
	par.appbufsz = 3 * par.round;
	par.bits = 32;
	par.rate = rate;
	par.pchan = rtp_nch;
	par.rchan = rtp_nch;

	if (!sio_setpar(hdl, &par) || !sio_getpar(hdl, &par)) {
		fprintf(stderr, "%s: failed to set parameters\n", dev);
		goto err_close;
	}

	if (par.bits != 32 || par.le != SIO_LE_NATIVE || par.rate != rate) {
		fprintf(stderr, "%s: unsupported audio parameters\n", dev);
		goto err_close;
	}

	if ((mode & SIO_PLAY) && par.pchan < rtp_nch) {
		fprintf(stderr, "%s: %d: unsupported playback chans\n", dev, par.pchan);
		goto err_close;
	}

	if ((mode & SIO_REC) && par.rchan != rtp_nch) {
		fprintf(stderr, "%s: %d: unsupported recording chans\n", dev, par.rchan);
		goto err_close;
	}

	if (mode & SIO_PLAY) {
		play_size = sizeof(int) * par.pchan * par.round;
		play_buf = malloc(play_size);
		if (play_buf == NULL) {
			perror("play_buf");
			exit(1);
		}
		play_start = play_end = 0;
		play_nch = par.pchan;
	}

	if (mode & SIO_REC) {
		rec_size = sizeof(int) * par.rchan * par.round;
		rec_buf = malloc(sizeof(int) * par.rchan * par.round);
		if (rec_buf == NULL) {
			fprintf(stderr, "%s: failed to allocate rec buffer\n", dev);
			goto err_close;
		}
		rec_start = rec_end = 0;
		rec_nch = par.rchan;

		data = malloc(rtp_bps * rtp_nch * par.round);
		if (data == NULL) {
			fprintf(stderr, "%s: failed to send pkt data\n", dev);
			goto err_close;
		}
	}

	if (rtp_bufsz < par.rate / 20)
		rtp_bufsz = par.rate / 20;
	if (rtp_bufsz < par.bufsz + par.round * 4)
		rtp_bufsz = par.bufsz + par.round * 4;
	rtp->rate = par.rate;

	for (i = 0; i < RTP_MAXSRC; i++) {
		src = malloc(sizeof(struct rtp_src));
		if (src == NULL) {
			perror("src");
			exit(1);
		}
		src->buf_len = 2 * rtp_bufsz;
		src->buf = malloc(src->buf_len * rtp_nch * sizeof(int));
		if (src->buf == NULL) {
			perror("src");
			exit(1);
		}
		src->next = rtp->src_freelist;
		rtp->src_freelist = src;
	}

	if (!sio_start(hdl)) {
		fprintf(stderr, "%s: failed to start\n", dev);
		goto err_close;
	}

	fprintf(stderr, "device period: %d samples\n", par.round);
	fprintf(stderr, "device buffer: %d samples\n", par.bufsz);
	fprintf(stderr, "packet buffer: %d samples\n", rtp_bufsz);
	fprintf(stderr, "mode:%s%s\n",
	  (mode & SIO_PLAY) ? " play" : "",
	  (mode & SIO_REC) ? " rec" : "");

	while (1) {
		pfds[0].fd = rtp->fd;
		pfds[0].events = POLLIN;
		nfds = 1;

		events = 0;
		if (mode & SIO_PLAY)
			events |= POLLOUT;
		if (mode & SIO_REC)
			events |= POLLIN;
		nfds += sio_pollfd(hdl, &pfds[1], events);

		n = poll(pfds, nfds, -1);
		if (n == -1) {
			perror("poll");
			exit(1);
		}

		if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1) {
			fprintf(stderr, "clock_gettime: %s\n", strerror(errno));
			exit(1);
		}
		rtp_time = 1000000000LL * ts.tv_sec + ts.tv_nsec;

		if (pfds[0].revents & POLLIN)
			rtp_recvpkt(rtp);

		events = sio_revents(hdl, &pfds[1]);
		if (events & POLLHUP)
			break;
		if (events & POLLOUT) {
			if (play_start == play_end) {
				play_start = 0;
				play_end = play_size;
				rtp_mixbuf(rtp, play_buf, par.round);
			}
			n = sio_write(hdl, play_buf + play_start, play_end - play_start);
			play_start += n;
		}
		if (events & POLLIN) {
			n = sio_read(hdl, rec_buf + rec_end, rec_size - rec_end);
			if (sio_eof(hdl)) {
				fprintf(stderr, "%s: device disconnected\n", dev);
				goto err_close;
			}
			rec_end += n;

			if (rec_end == rec_size) {
				rec_start = 0;
				rec_end = 0;

				p = data;
				q = rec_buf;
				for (i = 0; i < par.round; i++) {
					for (c = 0; c < par.rchan; c++) {
						s = *q++;
						*p++ = s >> 24;
						*p++ = s >> 16;
						if (rtp_bps == 3)
							*p++ = s >> 8;
					}
				}

				rtp_sendblk(rtp, data, par.round);
			}
		}
	}

err_close:
	sio_close(hdl);

	while ((src = rtp->src_list) != NULL) {
		rtp->src_list = src->next;
		src->next = rtp->src_freelist;
		rtp->src_freelist = src;
	}
	while ((src = rtp->src_freelist) != NULL) {
		rtp->src_freelist = src->next;
		free(src->buf);
		free(src);
	}
}

int
rtp_parseurl(const char *url, char *host, char *port)
{
	const char scheme[] = "rtp://";
	const char *sep;
	size_t len;

	if (strncasecmp(url, scheme, sizeof(scheme) - 1) != 0) {
		fprintf(stderr,  "%s: rtp://host[:port] scheme expected\n", url);
		return 0;
	}
	url += sizeof(scheme) - 1;

	sep = strchr(url,  '/');
	if (sep != NULL) {
		fprintf(stderr,  "%s: '/' not allowed\n", url);
		return 0;
	}

	sep = strrchr(url,  ':');
	if (sep == NULL) {
		strlcpy(port, RTP_DEFAULT_PORT, NI_MAXSERV);
		len = strlen(url);
	} else {
		strlcpy(port, sep + 1, NI_MAXSERV);
		len = sep - url;
	}

	if (url[0] == '[') {
		if (url[len - 1] != ']') {
			fprintf(stderr,  "%s: ']' expected\n", url);
			return 0;
		}
		url++;
		len -= 2;
	}
	if (len >= NI_MAXHOST) {
		fprintf(stderr,  "%s: hostname too long\n", url);
		return 0;
	}
	memcpy(host, url, len);
	host[len] = 0;

	return 1;
}

int
main(int argc, char **argv)
{
	struct rtp rtp;
	unsigned int bits = 24, rate = 48000, bufsz = 2400;
	char host[NI_MAXHOST], port[NI_MAXSERV];
	int listen = 0, c;

	while ((c = getopt(argc, argv, "b:l:r:v")) != -1) {
		switch (c) {
		case 'b':
			if (sscanf(optarg, "%u", &bits) != 1)
				goto bad_usage;
			if (bits != 16 && bits != 24) {
				fputs("only 16 and 24 bits are supported\n", stderr);
				exit(1);
			}
			break;
		case 'l':
			listen = 1;
			if (!rtp_parseurl(optarg, host, port))
				exit(1);
			break;
		case 'r':
			if (sscanf(optarg, "%u", &rate) != 1)
				goto bad_usage;
			if (rate < 8000 || rate > 192000) {
				fputs("rate must be in the 8000..192000 range", stderr);
				exit(1);
			}
			break;
		case 'v':
			verbose++;
			break;
		case 'z':
			if (sscanf(optarg, "%u", &bufsz) != 1)
				goto bad_usage;
			break;
		default:
			goto bad_usage;
		}
	}

	argc -= optind;
	argv += optind;

	if (!listen && argc == 0) {
	bad_usage:
		fputs("usage: sndiortp [-b bits] [-l url] [-r rate] [url ...]\n", stderr);
		exit(1);
	}

	rtp_init(&rtp, host, port, listen);

	rtp_bufsz = bufsz;
	rtp_bps = bits / 8;
	rtp_nch = 2;

	while (argc > 0) {
		if (!rtp_parseurl(argv[0], host, port))
			exit(1);
		rtp_mkdst(&rtp, host, port);
		argc--;
		argv++;
	}

	rtp_loop(&rtp, SIO_DEVANY, rate, listen);

	return 0;
}
