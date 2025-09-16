/*
 * Copyright (c) 2024 Alexandre Ratchov <alex@caoua.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <sndio.h>

#define RTP_MTU			1500
#define RTP_MAXDATA		(RTP_MTU - 68)	/* IPv6 has 68-byte headers */
#define RTP_DEFAULT_PORT	"5004"
#define RTP_MAXSRC		256
#define RTP_MAXCHAN		64
#define RTP_MULT		0x1000000

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
	struct rtp_sock {
		struct rtp_sock *next;
		int fd;
		int family;
		struct sockaddr_storage sa;
		socklen_t salen;
	} *send_sock_list, *recv_sock_list;

	struct rtp_src {
		struct rtp_src *next;
		unsigned int seq, ts, ssrc;
		int started;

		/* ring buffer with received samples */
		int *buf;
		size_t buf_start, buf_used, buf_len;

		/* local time of the last sample received */
		long long time;

		/*
		 * Estimated offset (in samples) between the play pointer
		 * and the last received sample. It's stored as a fixed-point
		 * number (multiplied by RTP_MULT).
		 */
		long long offs;
		long long offs_target;			/* inital value */
		long long offs_sum, offs_cnt;		/* averaging */

		/*
		 * Resampler to adjust stream frequency in order
		 * to reach the desired offset
		 */
		int diff;
		int freq;
		int samphist[RTP_MAXCHAN];

	} *src_list, *src_freelist;

	struct rtp_dst {
		struct rtp_dst *next;
		unsigned int seq, ts, ssrc;

		struct rtp_sock *sock;
	} *dst_list;

	int rate;
	size_t bps, nch, bufsz;
};

void logx(const char *fmt, ...) __attribute__((__format__ (printf, 1, 2)));

int resample = 1;
int verbose;
int quit;

unsigned char *play_buf;
size_t play_size, play_start, play_end;
unsigned int play_nch;

int *rec_buf;
size_t rec_size, rec_start, rec_end;
unsigned int rec_nch;

long long rtp_time, rtp_time_base;

const char usagestr[] = \
    "usage: sndiortp [-hvx] [-b nframes] [-c channels] [-f device]\n"
    "                [-l rtp://addr[:port]] [-p bits] [-r rate] [-z nframes]\n"
    "                [rtp://addr[:port] ...]\n";

const char helpstr[] =
    "\t-b receive buffer size\n"
    "\t-c RTP number of channels\n"
    "\t-f audio device name\n"
    "\t-l accept RTP streams on the given local address\n"
    "\t-h print this help screen\n"
    "\t-p RTP audio samples precision in bits\n"
    "\t-r RTP audio sample rate\n"
    "\t-v increase log verbosity\n"
    "\t-x don't adjust RTP source sample rate\n"
    "\t-z audio device block size\n";

/*
 * Log to stderr with with the current time as prefix
 */
void
logx(const char *fmt, ...)
{
	char buf[128];
	char *p = buf, *end = buf + sizeof(buf);
	va_list ap;
	int save_errno = errno;

	p += snprintf(buf, sizeof(buf), "%010lld.%09llu: ",
	    rtp_time / 1000000000, rtp_time % 1000000000);

	va_start(ap, fmt);
	p += vsnprintf(p, p < end ? end - p : 0, fmt, ap);
	va_end(ap);

	if (p >= end)
		p = end - 1;

	*p++ = '\n';
	write(STDERR_FILENO, buf, p - buf);

	errno = save_errno;
}

/*
 * SIGINT handler
 */
void
sigint(int s)
{
	if (quit)
		_exit(1);
	quit = 1;
}

/*
 * Return the current time in nanoseconds
 */
long long
rtp_gettime(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1) {
		logx("clock_gettime: %s", strerror(errno));
		exit(1);
	}

	return 1000000000LL * ts.tv_sec + ts.tv_nsec;
}

/*
 * Create a socket for the given address family (IP or IPV6) and
 * append it to the given list.
 */
struct rtp_sock *
rtp_addsock(struct rtp *rtp, struct rtp_sock **list, int family, struct sockaddr *sa, socklen_t salen)
{
	struct rtp_sock *sock;
	int fd, opt;

	sock = malloc(sizeof(struct rtp_sock));
	if (sock == NULL) {
		perror("sock");
		exit(1);
	}

	fd = socket(family, SOCK_DGRAM, IPPROTO_UDP);
	if (fd == -1) {
		logx("socket: %s", strerror(errno));
		exit(1);
	}

	if (family == AF_INET6) {
		/*
		 * make sure IPv6 sockets are restricted to IPv6
		 * addresses because we already use a IP socket
		 * for IP addresses
		 */
		opt = 1;
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
			&opt, sizeof(int)) == -1) {
			logx("setsockopt: IPV6_V6ONLY: %s", strerror(errno));
			exit(1);
		}
	}

	sock->fd = fd;
	sock->family = family;
	memcpy(&sock->sa, sa, salen);
	sock->salen = salen;
	sock->next = *list;
	*list = sock;

	return sock;
}

/*
 * Find the rtp_sock structure of the given address family (IP or IPV6).
 */
struct rtp_sock *
rtp_findsock(struct rtp *rtp, struct rtp_sock **list, int family, struct sockaddr *sa, socklen_t salen)
{
	struct rtp_sock *sock;

	for (sock = *list; sock != NULL; sock = sock->next) {
		if (sock->family == family &&
		    sock->salen == salen &&
		    memcmp(&sock->sa, sa, salen) == 0)
			return sock;
	}

	return NULL;
}

/*
 * Create a rtp_sock structure and bind the socket to the given address
 * and port
 */
void
rtp_bind(struct rtp *rtp, const char *host, const char *serv)
{
	struct addrinfo *ailist, *ai, aihints;
	struct rtp_sock *sock;
	int error;

	memset(&aihints, 0, sizeof(struct addrinfo));
	aihints.ai_family = AF_UNSPEC;
	aihints.ai_socktype = SOCK_DGRAM;
	aihints.ai_protocol = IPPROTO_UDP;
	aihints.ai_flags = AI_PASSIVE;

	error = getaddrinfo(host[0] ? host : NULL, serv, &aihints, &ailist);
	if (error) {
		logx("getaddrinfo: %s: %s", host, gai_strerror(error));
		exit(1);
	}

	for (ai = ailist; ai != NULL; ai = ai->ai_next) {

		if (rtp_findsock(rtp, &rtp->recv_sock_list,
			ai->ai_family, ai->ai_addr, ai->ai_addrlen))
			continue;

		sock = rtp_addsock(rtp, &rtp->recv_sock_list,
		    ai->ai_family, ai->ai_addr, ai->ai_addrlen);

		if (bind(sock->fd, ai->ai_addr, ai->ai_addrlen) == -1) {
			logx("bind: %s", strerror(errno));
			exit(1);
		}
	}

	freeaddrinfo(ailist);
}

/*
 * Add the RTP source with the given SSRC, sequence number, and time-stamp.
 */
struct rtp_src *
rtp_addsrc(struct rtp *rtp, unsigned int ssrc, unsigned int seq, unsigned int ts)
{
	struct rtp_src *src;

	src = rtp->src_freelist;
	if (src == NULL) {
		logx("out of free src structures");
		exit(1);
	}

	rtp->src_freelist = src->next;
	src->ssrc = ssrc;
	src->seq = seq;
	src->ts = ts;
	src->started = 0;
	src->buf_start = src->buf_used = 0;
	src->next = rtp->src_list;
	rtp->src_list = src;
	if (verbose >= 3)
		logx("ssrc 0x%x: created", src->ssrc);
	return src;
}

/*
 * Drop the given RTP source.
 */
void
rtp_dropsrc(struct rtp *rtp, struct rtp_src *src)
{
	struct rtp_src **psrc;

	psrc = &rtp->src_list;
	while (1) {
		if (src == NULL) {
			logx("ssrc 0x%x: not found", src->ssrc);
			exit(1);
		}
		if (src == *psrc) {
			*psrc = src->next;
			src->next = rtp->src_freelist;
			rtp->src_freelist = src;
			if (verbose >= 3)
				logx("ssrc 0x%x: dropped", src->ssrc);
			break;
		}
		psrc = &(*psrc)->next;
	}
}

/*
 * Find the RTP source with the given SSRC
 */
struct rtp_src *
rtp_findsrc(struct rtp *rtp, unsigned int ssrc)
{
	struct rtp_src *src;

	for (src = rtp->src_list; src != NULL; src = src->next) {
		if (src->ssrc == ssrc)
			break;
	}
	return src;
}

/*
 * Create a RTP destination for the given address and port
 */
int
rtp_mkdst(struct rtp *rtp, const char *host, const char *serv)
{
	struct rtp_dst *dst;
	struct addrinfo *ailist, *ai, aihints;
	int error;

	memset(&aihints, 0, sizeof(struct addrinfo));
	aihints.ai_family = AF_UNSPEC;
	aihints.ai_socktype = SOCK_DGRAM;
	aihints.ai_protocol = IPPROTO_UDP;
	error = getaddrinfo(host, serv, &aihints, &ailist);
	if (error) {
		logx("getaddrinfo: %s: %s", host, gai_strerror(error));
		exit(1);
	}

	ai = ailist;

	dst = malloc(sizeof(struct rtp_dst));
	if (dst == NULL) {
		perror("dst");
		exit(1);
	}

	dst->seq = arc4random();
	dst->ts = arc4random();
	dst->ssrc = arc4random();

	dst->sock = rtp_findsock(rtp, &rtp->send_sock_list,
	    ai->ai_family, ai->ai_addr, ai->ai_addrlen);

	if (dst->sock == NULL) {
		dst->sock = rtp_addsock(rtp, &rtp->send_sock_list,
		    ai->ai_family, ai->ai_addr, ai->ai_addrlen);
	}

	dst->next = rtp->dst_list;
	rtp->dst_list = dst;

	freeaddrinfo(ai);
	return 1;
}

/*
 * Retrieve the next packet from the given socket. Find the corresponding
 * RTP source structure (create one if this is a new source) and copy the
 * payload to its ring buffer.
 *
 * Retrun 0 if no packet could be retrieved (socket is blocking).
 */
int
rtp_recvpkt(struct rtp *rtp, struct rtp_sock *sock)
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

	size = recvmsg(sock->fd, &msg, MSG_DONTWAIT);
	if (size == -1) {
		if (errno == EAGAIN)
			return 0;
		logx("recvmsg: %s", strerror(errno));
		exit(1);
	}

	if (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
		logx("recvmsg: truncated");
		exit(1);
	}

	if (size < sizeof(struct rtp_hdr)) {
		logx("%zd: pkt size too short", size);
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
		logx("%d: unsupported version", version);
		exit(1);
	}

	if (type != 96) {
		logx("%d: unexpected payload type", type);
		exit(1);
	}

	if (flags & (1 << RTP_PADDING)) {
		logx("rtp padding not supported");
		exit(1);
	}

	if (flags & (1 << RTP_EXTENSION)) {
		hdrext = ntohl(*(uint32_t *)(u.buf + offs));
		offs += 4 * (1 + (hdrext & 0xffff));
	}

	src = rtp_findsrc(rtp, ssrc);
	if (src != NULL) {
		if (seq != src->seq) {
			if (verbose) {
				logx("ssrc 0x%x: %u: bad seq number (expected %u)",
				    src->ssrc, seq, src->seq);
			}
			rtp_dropsrc(rtp, src);
			return 1;
		}
		if (ts != src->ts) {
			if (verbose) {
				logx("ssrc 0x%x: %u: bad time-stamp (expected %u)",
				    src->ssrc, ts, src->ts);
			}
			rtp_dropsrc(rtp, src);
			return 1;
		}
	} else
		src = rtp_addsrc(rtp, ssrc, seq, ts);

	data = u.buf + offs;
	nsamp = (size - offs) / (rtp->bps * rtp->nch);

	src->ts += nsamp;
	src->seq = (src->seq + 1) & 0xffff;

	while (nsamp > 0) {

		if (src->buf_used >= src->buf_len) {
			if (verbose)
				logx("ssrc 0x%x: overflow", src->ssrc);
			rtp_dropsrc(rtp, src);
			return 1;
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
		p = src->buf + end * rtp->nch;

		for (i = count; i > 0; i--) {
			for (j = rtp->nch; j > 0; j--) {
				s = data[0] << 24 | data[1] << 16;
				if (rtp->bps == 3)
					s |= data[2] << 8;
				data += rtp->bps;
				(*p++) = s;
			}
		}

		nsamp -= count;
		src->buf_used += count;
	}

	src->time = rtp_time;
	return 1;
}

/*
 * Send the given RTP payload to all RTP destinations.
 */
void
rtp_sendpkt(struct rtp *rtp, void *data, unsigned int count)
{
	struct rtp_dst *dst;
	struct rtp_hdr hdr;
	struct msghdr msg;
	struct iovec iov[2];
	size_t size;
	ssize_t n;
	int dropped = 0;

	for (dst = rtp->dst_list; dst != NULL; dst = dst->next) {

		size = count * rtp->bps * rtp->nch;

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
		msg.msg_name = &dst->sock->sa;
		msg.msg_namelen = dst->sock->salen;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_iov = iov;
		msg.msg_iovlen = 2;

		n = sendmsg(dst->sock->fd, &msg, MSG_DONTWAIT);
		if (n == -1) {
			if (errno != EAGAIN) {
				logx("sendmsg: %s", strerror(errno));
				exit(1);
			}
			dropped++;
			continue;
		}
		if (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
			logx("sendmsg: truncated");
			exit(1);
		}
	}
	if (dropped > 0) {
		if (verbose)
			logx("dropped %d pkts", dropped);
	}
	if (verbose >= 3)
		logx("sent %d samples", count);
}

/*
 * Send the given block of audio samples to all RTP destinations,
 * possibly splitting the block into multiple packets.
 */
void
rtp_sendblk(struct rtp *rtp, int *data, unsigned int nsamp)
{
	unsigned char pktdata[RTP_MAXDATA];
	unsigned char *p;
	int *q;
	unsigned int npkt, pktsz, maxsamp, maxpktsz;
	unsigned int bpf;
	int i, c, s;

	bpf = rtp->bps * rtp->nch;
	maxsamp = RTP_MAXDATA / bpf;
	npkt = (nsamp + maxsamp - 1) / maxsamp;
	maxpktsz = (nsamp + npkt - 1) / npkt;

	if (verbose >= 3)
		logx("sending %d bytes (%d pkts)", nsamp * bpf, npkt);

	q = data;
	while (nsamp > 0) {
		pktsz = maxpktsz;
		if (pktsz > nsamp)
			pktsz = nsamp;

		p = pktdata;
		for (i = 0; i < pktsz; i++) {
			for (c = 0; c < rtp->nch; c++) {
				s = *q++;
				*p++ = s >> 24;
				*p++ = s >> 16;
				if (rtp->bps == 3)
					*p++ = s >> 8;
			}
			q += rec_nch - rtp->nch;
		}

		rtp_sendpkt(rtp, pktdata, pktsz);
		nsamp -= pktsz;
		data += pktsz;
	}
}

/*
 * Return the estimated offset, i.e. the number of samples buffered plus
 * the time elapsed since we received the last sample
 */
long long
rtp_srcoffs(struct rtp *rtp, struct rtp_src *src)
{
	return src->buf_used +
	    ((rtp_time - src->time) * rtp->rate + 500000000LL) / 1000000000LL;
}

/*
 * Produce (and mix) a block of audio samples from the given RTP source.
 * The source is resampled to keep the offset between the audio device
 * pointer and the RTP receive pointer constant.
 */
void
rtp_mixsrc(struct rtp *rtp, struct rtp_src *src, int *mixbuf, size_t todo)
{
	size_t j;
	long long s, offs, avg, cnt;
	int *q;

	if (!src->started) {
		if (src->buf_used < rtp->bufsz)
			return;
		if (verbose)
			logx("ssrc 0x%x: started", src->ssrc);
		src->started = 1;
		src->freq = RTP_MULT;
		src->diff = RTP_MULT;
		src->offs = RTP_MULT * rtp_srcoffs(rtp, src);
		src->offs_target = src->offs;
		src->offs_cnt = 0;
		src->offs_sum = 0;
	}

	src->offs_cnt += todo;
	src->offs_sum += todo * rtp_srcoffs(rtp, src);

	if (src->offs_cnt >= rtp->rate / 8) {

		/*
		 * estimate the time offset: calculate
		 * the average offset over around 1 second (8 times
		 * 1/8th of a second).
		 */

		/* save the old offset */
		offs = src->offs;

		/* average offset over the last 1/8th of second */
		avg = RTP_MULT * (src->offs_sum + src->offs_cnt / 2) / src->offs_cnt;

		/* low-pass the average offset, ~1 second decay time */
		src->offs = (7 * src->offs + avg + 4) / 8;

		/*
		 * calculate resampling frequency that will
		 * compensate the offset in roughly 128 seconds
		 */
		if (resample) {
			cnt = RTP_MULT * src->offs_cnt;
			src->freq = src->freq *
			    (cnt - (src->offs - src->offs_target) / 128) /
			    (cnt + (src->offs - offs));
		}

		if (verbose >= 2) {
			logx("err = %+.3f / %.3f, freq = %.17f",
			    (double)(src->offs - src->offs_target) / RTP_MULT,
			    (double)src->offs_target / RTP_MULT,
			    (double)src->freq / RTP_MULT);
		}

		src->offs_cnt = 0;
		src->offs_sum = 0;
	}

	/*
	 * Resample and add the data to 'mixbuf'.
	 */
	while (todo > 0) {
		if (src->diff >= src->freq) {
			if (src->buf_used == 0) {
				if (verbose)
					logx("ssrc 0x%x: stopped", src->ssrc);
				rtp_dropsrc(rtp, src);
				break;
			}

			q = src->buf + src->buf_start * rtp->nch;
			for (j = 0; j < rtp->nch; j++) {
				src->samphist[j] = q[j];
			}

			src->buf_used--;
			src->buf_start++;
			if (src->buf_start >= src->buf_len)
				src->buf_start -= src->buf_len;

			src->diff -= src->freq;
		} else {
			for (j = 0; j < rtp->nch; j++) {
				s = src->samphist[j] + mixbuf[j];
				if (s > INT_MAX)
					s = INT_MAX;
				if (s < -INT_MAX)
					s = -INT_MAX;
				mixbuf[j] = s;
			}
			mixbuf += play_nch;

			src->diff += RTP_MULT;
			todo--;
		}
	}
}

/*
 * Prodice a block of audio samples by mixing all RTP sources
 */
void
rtp_mixbuf(struct rtp *rtp, void *mixbuf, size_t count)
{
	struct rtp_src *src, *srcnext;

	memset(mixbuf, 0, count * play_nch * sizeof(int));

	for (src = rtp->src_list; src != NULL; src = srcnext) {
		srcnext = src->next;
		rtp_mixsrc(rtp, src, mixbuf, count);
	}
}

/*
 * Initialize the rtp structure.
 */
void
rtp_init(struct rtp *rtp)
{
	struct rtp_src *src;
	int i;

	rtp->recv_sock_list = NULL;
	rtp->send_sock_list = NULL;
	rtp->src_list = rtp->src_freelist = NULL;
	rtp->dst_list = NULL;

	rtp->rate = 48000;
	rtp->bufsz = 2400;
	rtp->bps = 3;
	rtp->nch = 2;
}

/*
 * Free resources
 */
void
rtp_done(struct rtp *rtp)
{
	struct rtp_sock *sock;
	struct rtp_dst *dst;
	struct rtp_src *src;

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
	while ((dst = rtp->dst_list) != NULL) {
		rtp->dst_list = dst->next;
		free(dst);
	}
	while ((sock = rtp->recv_sock_list) != NULL) {
		rtp->recv_sock_list = sock->next;
		close(sock->fd);
		free(sock);
	}
	while ((sock = rtp->send_sock_list) != NULL) {
		rtp->send_sock_list = sock->next;
		close(sock->fd);
		free(sock);
	}
}

/*
 * Prepare for real-time operation: set sample rate, buffer size, preallocate
 * any structures accordingly.
 */
void
rtp_start(struct rtp *rtp, unsigned int bits, unsigned int nch, unsigned int rate, size_t bufsz)
{
	struct rtp_src *src;
	int i;

	rtp->bufsz = bufsz;
	rtp->bps = bits / 8;
	rtp->nch = nch;
	rtp->rate = rate;

	for (i = 0; i < RTP_MAXSRC; i++) {
		src = malloc(sizeof(struct rtp_src));
		if (src == NULL) {
			perror("src");
			exit(1);
		}
		src->buf_len = 2 * rtp->bufsz;
		src->buf = malloc(src->buf_len * rtp->nch * sizeof(int));
		if (src->buf == NULL) {
			perror("src->buf");
			exit(1);
		}
		src->next = rtp->src_freelist;
		rtp->src_freelist = src;
	}
}

/*
 * Parse a rtp://host[:port] URL.
 */
int
rtp_parseurl(const char *url, char *host, char *serv)
{
	const char scheme[] = "rtp://";
	const char *p = url, *tok, *end;
	size_t len;

	if (strncasecmp(p, scheme, sizeof(scheme) - 1) != 0) {
		fprintf(stderr,  "%s: rtp://host[:port] scheme expected\n", url);
		return 0;
	}
	p += sizeof(scheme) - 1;

	if (*p == '[') {
		tok = p + 1;
		end = strchr(tok, ']');
		if (end == NULL) {
			fprintf(stderr,  "%s: ending ']' expected\n", url);
			return 0;
		}
		len = end - tok;
		p += len + 2;
	} else {
		tok = p;
		len = strcspn(p, ":/");
		p += len;
	}

	if (len >= NI_MAXHOST) {
		fprintf(stderr,  "%s: host component too long\n", url);
		return 0;
	}
	memcpy(host, tok, len);
	host[len] = 0;

	if (*p == ':') {
		tok = ++p;
		len = strcspn(tok, "/");
		if (len >= NI_MAXSERV) {
			fprintf(stderr,  "%s: service component too long\n", url);
			return 0;
		}
		memcpy(serv, tok, len);
		serv[len] = 0;
		p += len;
	} else
		snprintf(serv, NI_MAXSERV, "%s", RTP_DEFAULT_PORT);

	if (*p != 0) {
		fprintf(stderr,  "%s: '/' not allowed\n", url);
		return 0;
	}

	return 1;
}

void
mainloop(struct rtp *rtp, const char *dev, unsigned int blksz)
{
	struct rtp_sock *sock;
	struct pollfd *pfds;
	struct sio_hdl *hdl;
	struct sio_par par;
	size_t nfds;
	int events, n;
	unsigned int mode;

	/*
	 * count the number of descriptor to poll for incoming packets
	 */
	nfds = 0;
	for (sock = rtp->recv_sock_list; sock != NULL; sock = sock->next)
		nfds++;

	mode = 0;
	if (nfds > 0)
		mode |= SIO_PLAY;
	if (rtp->dst_list)
		mode |= SIO_REC;

	hdl = sio_open(dev, mode, 1);
	if (hdl == NULL) {
		logx("%s: failed to open audio device", dev);
		return;
	}

	pfds = malloc((sio_nfds(hdl) + nfds) * sizeof(struct pollfd));
	if (pfds == NULL) {
		perror("pfds");
		exit(1);
	}

	sio_initpar(&par);
	par.round = blksz;
	par.appbufsz = 2 * par.round;
	par.bits = 32;
	par.rate = rtp->rate;
	par.pchan = rtp->nch;
	par.rchan = rtp->nch;

	if (!sio_setpar(hdl, &par) || !sio_getpar(hdl, &par)) {
		logx("%s: failed to set parameters", dev);
		goto err_close;
	}

	if (par.bits != 32 || par.le != SIO_LE_NATIVE || par.rate != rtp->rate) {
		logx("%s: unsupported audio parameters", dev);
		goto err_close;
	}

	if ((mode & SIO_PLAY) && par.pchan < rtp->nch) {
		logx("%s: %d: unsupported playback chans", dev, par.pchan);
		goto err_close;
	}

	if ((mode & SIO_REC) && par.rchan < rtp->nch) {
		logx("%s: %d: unsupported recording chans", dev, par.rchan);
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
			logx("%s: failed to allocate rec buffer", dev);
			goto err_close;
		}
		rec_start = rec_end = 0;
		rec_nch = par.rchan;
	}

	logx("device period: %d samples", par.round);
	logx("device buffer: %d samples", par.appbufsz);
	logx("packet buffer: %zd samples", rtp->bufsz);
	logx("mode:%s%s",
	  (mode & SIO_PLAY) ? " play" : "",
	  (mode & SIO_REC) ? " rec" : "");

	if (mlockall(MCL_CURRENT | MCL_FUTURE) == -1)
		perror("mlockall");

	if (!sio_start(hdl)) {
		logx("%s: failed to start", dev);
		goto err_close;
	}

	while (1) {
		if (quit)
			break;

		nfds = 0;
		for (sock = rtp->recv_sock_list; sock != NULL; sock = sock->next) {
			pfds[nfds].fd = sock->fd;
			pfds[nfds].events = POLLIN;
			nfds++;
		}

		events = 0;
		if (mode & SIO_PLAY)
			events |= POLLOUT;
		if (mode & SIO_REC)
			events |= POLLIN;
		nfds += sio_pollfd(hdl, &pfds[nfds], events);

		n = poll(pfds, nfds, -1);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			perror("poll");
			exit(1);
		}

		rtp_time = rtp_gettime() - rtp_time_base;

		nfds = 0;
		for (sock = rtp->recv_sock_list; sock != NULL; sock = sock->next) {
			if (pfds[nfds].revents & POLLIN) {
				while (rtp_recvpkt(rtp, sock))
					;
			}
			nfds++;
		}

		events = sio_revents(hdl, &pfds[nfds]);
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
				logx("%s: device disconnected", dev);
				goto err_close;
			}
			rec_end += n;

			if (rec_end == rec_size) {
				rtp_sendblk(rtp, rec_buf, par.round);
				rec_start = 0;
				rec_end = 0;
			}
		}
	}

	logx("terminating");
	munlockall();

err_close:
	free(rec_buf);
	free(play_buf);
	free(pfds);
	sio_close(hdl);
}

int
main(int argc, char **argv)
{
	struct rtp rtp;
	struct sigaction sa;
	unsigned int bits = 24, rate = 48000, nch = 2, blksz = 0, bufsz = 0;
	char host[NI_MAXHOST], port[NI_MAXSERV];
	const char *dev = SIO_DEVANY;
	int c;

	rtp_init(&rtp);

	while ((c = getopt(argc, argv, "b:c:f:hl:p:r:vxz:")) != -1) {
		switch (c) {
		case 'b':
			if (sscanf(optarg, "%u", &bufsz) != 1)
				goto bad_usage;
			break;
		case 'c':
			if (sscanf(optarg, "%u", &nch) != 1)
				goto bad_usage;
			if (nch < 1 || nch > RTP_MAXCHAN) {
				fputs("channels must be in the 1..256 range", stderr);
				exit(1);
			}
			break;
		case 'p':
			if (sscanf(optarg, "%u", &bits) != 1)
				goto bad_usage;
			if (bits != 16 && bits != 24) {
				fputs("only 16 and 24 bits are supported\n", stderr);
				exit(1);
			}
			break;
		case 'f':
			dev = optarg;
			break;
		case 'h':
			fputs(usagestr, stderr);
			fputs(helpstr, stderr);
			exit(0);
			break;
		case 'l':
			if (!rtp_parseurl(optarg, host, port))
				exit(1);
			rtp_bind(&rtp, host, port);
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
		case 'x':
			resample = 0;
			break;
		case 'z':
			if (sscanf(optarg, "%u", &blksz) != 1)
				goto bad_usage;
			break;
		default:
			goto bad_usage;
		}
	}

	if (blksz == 0)
		blksz = rate / 100;
	if (bufsz == 0)
		bufsz = rate / 20;

	argc -= optind;
	argv += optind;

	while (argc > 0) {
		if (!rtp_parseurl(argv[0], host, port))
			exit(1);
		rtp_mkdst(&rtp, host, port);
		argc--;
		argv++;
	}

	if (rtp.recv_sock_list == NULL && rtp.send_sock_list == NULL) {
	bad_usage:
		fputs(usagestr, stderr);
		exit(1);
	}

	sigfillset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = sigint;
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		perror("sigaction(int) failed");
		exit(1);
	}

	rtp_start(&rtp, bits, nch, rate, bufsz);
	rtp_time_base = rtp_gettime();

	mainloop(&rtp, dev, blksz);

	rtp_done(&rtp);
	return 0;
}
