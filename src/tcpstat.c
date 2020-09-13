/*
 * Copyright (c) 2000 Paul Herman
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: tcpstat.c,v 1.61 2002/07/27 00:42:05 pherman Exp $
 */

#include "tcpstat.h"

#define KIL		(1024)
#define MEG		(1024*1024)
#define GIG		(1024*1024*1024)
#define Double		double		/* FP accuracy */
#define DEFAULT_INTERVAL	5
#define DEFAULT_FORMAT		"Time:%S\tn=%n\tavg=%a\tstddev=%d\tbps=%b\n"
#define SETUID_WARNING			\
"\n \
 \n \
 \n*** Warning!!  tcpstat is running setuid!  This is not recommended.	\
 \n*** I will disable the ability to write to arbitrary file descriptors. \
 \n \
"

enum {
	ACTION_INTERVAL, ACTION_BANDWIDTH, ACTION_ACCOUNT, ACTION_LOAD
};

/**
 **	GLOBALS - mostly options to be set on the command line
 **/
char action			= ACTION_INTERVAL;
char *filterexpr = NULL;
char *outputformat = NULL;
Double	interval;
Double	relative_seconds	= 0.0;
Double	bandwidth		= 0.0;
Double	peakbandwidth		= 0.0;
int	get_tcp_flags		= 0;	/* flags to pass to get_dump_data */
int	flush_stdout		= 0;	/* flushes all fds when set */
int	smart_bandwidth		= 0;	/* when set, use smart bandwidth mode */
int	empty_intervals		= 1;	/* by default print empty intervals */
int	is_setuid		= 0;	/* refuse to use fdescs when setuid */
int	print_immediately	= 0;	/* flag set when SIGUSR1 received */
Double	capture_seconds		= -1.0;	/* -1.0 means infinite */

/*
 * This is the main structure that keeps track of all the statistics
 */
typedef struct statistics {
	struct {
		Double		ts_bigbang;
		Double		total_time;
		Double		total_time_over_bps;
		Double		total_bytes;
		} global;
	struct {
		int		packets;
		int		arp;
		int		ip;
#ifdef INET6
		int		ip6;
#endif
		int		tcp;
		int		udp;
		int		icmp;
		} count;
	int	max_packetsize;	/* maximum packet size over the interval */
	int	min_packetsize;	/* mininum packet size over the interval */
	Double	ts_interval_begin; /* timestamp of the first packet in the interval */
	Double	ts_now;		/* timestamp of last packet received */
	Double	sum;		/* sum of of the packet sizes */
	Double	sum2;		/* sum of the squares of the packet sizes */
	Double	smartb_sum;	/* bytes carried over from the last interval */
	Double	load;		/* bps averaged over 1 minute */
} statistics;

/*
 * Handy routine to return a string of only numbers.
 */
char *my_get_nr(char *f) {
	static char s[BUF_SIZ];
	char *p;
	int i = 0;

	if (f == NULL) return NULL;
	p = f;
	while (*p && isdigit(*p) ) { i++; p++; }
	i = (i > (BUF_SIZ-1)) ? BUF_SIZ - 1 : i;	/* min(BUF_SIZ,i) */
	*s = 0;
	strncat(s, f, i);
	return s;
}

/*
 * Handy routine to print bytes in a human readable format.
 */
char *wr_bytes(Double b) {
	static char s[BUF_SIZ];
        if (0) {
                snprintf(s, BUF_SIZ, "%12.0f Bytes", b); return s;  }
        if ( b > GIG )  {
                snprintf(s, BUF_SIZ, "%8.1f GB", b/GIG); return s;  }
        if ( b > MEG )  {
                snprintf(s, BUF_SIZ, "%8.1f MB", b/MEG); return s;  }
        if ( b > KIL )  {
                snprintf(s, BUF_SIZ, "%8.1f KB", b/KIL); return s;  }
        snprintf(s, BUF_SIZ, "%8.1f  B", b); return s;
}

void catch_signal(int a) {
	switch (a) {
		case SIGUSR1:
			print_immediately = 1;
			break;
		default:
			break;
		}
}

/*
 * Parses the output format, and displays appropriate statistics
 */
void show_interval(statistics *s, Double dt) {
	char *f, *fd_str;
	Double avg, stddev, t_bar, delta_t;

	/* Used in the PRINTVAL macro which follows */
	char printval_str[BUF_SIZ];
	int filedesc = 1;

	/* Handy macro for writing bytes to arbitrary file descriptors */
#define PRINTVAL(x,y)	{			\
	snprintf(printval_str, BUF_SIZ, (x),(y));	\
	write(filedesc, printval_str, strlen(printval_str));	\
	}

	if (action != ACTION_INTERVAL) return;

	if (s->count.packets == 0) {
		avg = 0;
		stddev = 0;
		}
	else {
		avg = s->sum/(Double)s->count.packets;
		stddev = sqrt(s->sum2/(Double)s->count.packets - avg*avg);
		}
	delta_t = (interval == -1)? (s->ts_now - s->ts_interval_begin) : dt;
	t_bar = s->ts_interval_begin + delta_t/2.0;
	f = outputformat;
	while (*f) {
		if (*f == '%') {
			switch (*(++f)) {
				case 'A':
					PRINTVAL("%d", s->count.arp);
					break;
				case 'a':
					PRINTVAL("%.2f", avg);
					break;
				case 'B':
					PRINTVAL("%.2f", s->sum/delta_t);
					break;
				case 'b':
					PRINTVAL("%.2f", s->sum/delta_t * 8.0);
					break;
				case 'C':
					PRINTVAL("%d", s->count.icmp);
					break;
				case 'd':
					PRINTVAL("%.2f", stddev);
					break;
				case 'I':
					PRINTVAL("%d", s->count.ip);
					break;
				case 'l':
					PRINTVAL("%.2f", (peakbandwidth == 0.0)? 1.0 : s->load/peakbandwidth);
					break;
				case 'n':
					PRINTVAL("%d", s->count.packets);
					break;
				case 'M':
					PRINTVAL("%d", s->max_packetsize);
					break;
				case 'm':
					PRINTVAL("%d", s->min_packetsize);
					break;
				case 'N':
					PRINTVAL("%.0f", s->sum);
					break;
				case 'p':
					PRINTVAL("%.2f", (Double)s->count.packets/delta_t);
					break;
				case 'S':
					PRINTVAL("%d",
			(int) (t_bar + 0.5 - relative_seconds) );
					break;
				case 's':
					PRINTVAL("%.6f", t_bar - relative_seconds);
					break;
				case 'R':
					PRINTVAL("%d",
			(int) (t_bar + 0.5 - (relative_seconds
				 + s->global.ts_bigbang) ) );
					break;
				case 'r':
					PRINTVAL("%.6f", t_bar - 
						(relative_seconds + s->global.ts_bigbang));
					break;
				case 'T':
					PRINTVAL("%d", s->count.tcp);
					break;
				case 'U':
					PRINTVAL("%d", s->count.udp);
					break;
#ifdef INET6
				case 'V':
					PRINTVAL("%d", s->count.ip6);
					break;
#endif
				default:
					/* Check for file descriptor change */
					if (isdigit(*f)) {
						fd_str = my_get_nr(f);
#ifndef NO_FILEDESC
						if (!is_setuid) {
						  filedesc = strtol(fd_str, NULL, 10);
						  if (filedesc>256)
							filedesc = 1;
						  }
#endif /* NO_FILEDESC */
						f += strlen(fd_str) - 1;
						}
					else PRINTVAL("%%%c", *f);
					break;
				}	/* switch */
			} /* if %  */
		else if (*f == '\\') {
			switch (*(++f)) {
			/* XXX: This could be written better */
				case 'a': PRINTVAL("%s", "\a"); break;
				case 'b': PRINTVAL("%s", "\b"); break;
				case 'f': PRINTVAL("%s", "\f"); break;
				case 'n': PRINTVAL("%s", "\n"); break;
				case 'r': PRINTVAL("%s", "\r"); break;
				case 't': PRINTVAL("%s", "\t"); break;
				case 'v': PRINTVAL("%s", "\v"); break;
				default: PRINTVAL("%c", *f); break;
				}
			}
		else PRINTVAL("%c", *f);
		f++;
		}
	if (flush_stdout) fflush(NULL);
}

/*
 * Stores zeros in the given statistics structure
 */
void reset_counters(statistics *sp) {
	sp->count.packets	= 0;
	sp->sum			= 0.0;
	sp->sum2		= 0.0;
	sp->smartb_sum		= 0.0;
		/* Zero all counters */
	bzero(&sp->count, sizeof(sp->count));

	sp->max_packetsize	= 0;
	sp->min_packetsize	= 0;
}


/* This function updates all internal parameters
 * (peakbandwidth, load, etc.) and prints intervals
 * if neccesary
 */
int do_the_printing(statistics *sp, Double elapsed, Double ts) {
	statistics	zero;
	Double		x, bps;

	/* if this is a normal interval, i.e. one where the alarm
	 * timer ran up, just take the theoretical interval length.
	 * Otherwise, our best guess is the time elapsed between two
	 * packets.
	 */
	if (!print_immediately && interval > 0.0)
		elapsed = interval;

			/* Plain Bandwidth */
	bps = (sp->sum / elapsed) * 8.0;
	if (bps > peakbandwidth) peakbandwidth = bps;

		/* calculate the bandwidth load, if any */
	if (sp->load == -1.0) sp->load = bps;
	sp->load += (bps - sp->load) * (1.0 - exp(-elapsed/60.0));

		/* Smart bandwidth, if any */
	sp->sum += sp->smartb_sum;
	bps = (sp->sum / elapsed) * 8.0;
	if (bps > bandwidth) sp->global.total_time_over_bps += elapsed;

		/* show interval and reset stats */
	if (empty_intervals || sp->count.packets > 0)
		show_interval(sp, elapsed);
	sp->ts_interval_begin += elapsed;
	sp->global.total_time += elapsed;

		/* Now, pad the output with zeros, if neccesary */
	reset_counters(&zero);
	zero.global.ts_bigbang = sp->global.ts_bigbang;
	zero.load = sp->load;
	for (x = sp->ts_interval_begin + interval; x<ts && interval != -1.0; x += interval) {
		zero.ts_interval_begin = x - interval;
		sp->ts_interval_begin += interval;
		sp->global.total_time += interval;
		zero.load -= zero.load * (1.0 - exp(-interval/60.0));
		if (empty_intervals) show_interval(&zero, interval);
		}
	sp->load = zero.load;
	reset_counters(sp);
	if (smart_bandwidth && action == ACTION_BANDWIDTH
		&& bps > bandwidth) {
			/* Transfer the rest of the data over to
			 * the next interval.  This doesn't work
			 * for the packet count, but that's
			 * OK in bandwidth mode.
			 */
		sp->smartb_sum = (bps - bandwidth) * elapsed / 8.0;
		}
	/* Reset signal state */
	print_immediately = 0;
	return 0;
}

/*
 * This fuction is called by pcap_loop (not really, but OK.)  It adds
 * a particular packet to the total statistical data.
 */
void my_hook(packet_data *pd, void **args) {
	statistics	*sp;
	Double		ts, elapsed;

	sp = (statistics *) args[0];

	ts = 	(Double)pd->timestamp.tv_sec +
		(Double)pd->timestamp.tv_usec/1.0e6;

	if (sp->ts_interval_begin == 0.0) {
			/* initialize stats if called for the first time */
		reset_counters(sp);
		sp->ts_interval_begin	= ts;
		sp->global.ts_bigbang	= ts;
		}

		/* Before we add this packet to the statistics,
		 * we need to check if we are actually done counting
		 * packets.  This should only happen (and be useful)
		 * when reading data from a file.
		 */
	if (capture_seconds > 0.0 &&
	    ts - sp->global.ts_bigbang > capture_seconds)
		return;

		/* After that, we need to see if there is an interval waiting
		 * to be printed.
		 */
	elapsed = ts - sp->ts_interval_begin;
	if ( (elapsed > interval && interval != -1.0) ||
		(print_immediately && elapsed > 0.0) ) {

		/* We got a packet past the boundry of the last interval,
		 * so update stats, and print out the last interval that
		 * has already expired.  There might be a packet handed to
		 * this function at this point, but we can't include it in
		 * the current statistic.
		 */
		do_the_printing(sp, elapsed, ts);
		}
	sp->ts_now = ts;
	sp->count.packets++;
	sp->global.total_bytes += (Double)pd->packet_len;
	sp->sum += (Double)pd->packet_len;
	sp->sum2 += (Double)pd->packet_len * (Double)pd->packet_len;
/*	sp->sum2 = sp->sum * sp->sum; */

	if (is_ethernetarp_packet(pd)) (sp->count.arp)++;
	else {
		if (is_ip_packet(pd)) (sp->count.ip)++;
#ifdef INET6
		if (is_ip6_packet(pd)) (sp->count.ip6)++;
#endif
		if (is_ip_tcp_packet(pd)) sp->count.tcp++;
		if (is_ip_udp_packet(pd)) sp->count.udp++;
		if (is_ip_icmp_packet(pd)) sp->count.icmp++;
		}

	if ((int)pd->packet_len > sp->max_packetsize)
		sp->max_packetsize = pd->packet_len;
	if ((int)pd->packet_len < sp->min_packetsize || sp->min_packetsize == 0)
		sp->min_packetsize = pd->packet_len;
}

/*
 * process_file() gets the data, and then displays the statistics
 */
void process_file(char *fname, u_int unused) {
	void		*argv[2];
	statistics	stats;
	Double		x;

	signal(SIGUSR1, catch_signal);

	reset_counters(&stats);
	stats.ts_interval_begin	= 0.0;
	stats.load		= -1.0;
	stats.global.ts_bigbang	= 0.0;
	stats.global.total_bytes = 0.0;
	stats.global.total_time	= 0.0;
	stats.global.total_time_over_bps = 0.0;

	argv[0] = (void *) &stats;

		/* Main Loop */
        if (get_dump_data(fname, filterexpr, get_tcp_flags,
		    capture_seconds, my_hook, argv))
		return;

	/* The last "interval" still needs to be computed.
	 * Most of the work has been done.  Now do...
	 */
	x = (interval <= 0.0)? stats.ts_now - stats.global.ts_bigbang : interval;
	stats.global.total_time += x;

	do_the_printing(&stats, x, stats.ts_now);

	switch (action) {
		case ACTION_INTERVAL:
				/* If capture_seconds specified, do zero
				 * padding.  This is only useful when
				 * reading data from a file.
				 */
			if (capture_seconds > 0.0) {
				while (stats.ts_now + x - stats.global.ts_bigbang < capture_seconds) {
					do_the_printing(&stats, x, stats.ts_now);
					stats.global.total_time += x;
					stats.ts_now += x;
					}
				}
			break;
		case ACTION_BANDWIDTH:
			printf(
	"%sTime exceeding %.2f bps:\t%.2f sec.\t(%.2f%% of the time)\n",
				(smart_bandwidth)? "" : "(Raw) ",
				bandwidth,
				stats.global.total_time_over_bps,
				100 * stats.global.total_time_over_bps / 
				  stats.global.total_time );
			printf("Peak Bandwidth: %.2f bps\n", peakbandwidth);
			break;
		case ACTION_ACCOUNT:
			if (stats.global.total_time != 0.0)
				x = stats.global.total_bytes/stats.global.total_time;
			else x = stats.global.total_bytes/interval;
			printf("Bytes/sec\t= %s\n", wr_bytes(x));
			printf("Bytes/minute\t= %s\n", wr_bytes(x*60));
			printf("Bytes/hour\t= %s\n", wr_bytes(x*60*60));
			printf("Bytes/day\t= %s\n", wr_bytes(x*60*60*24));
			printf("Bytes/month\t= %s\n", wr_bytes(x*60*60*24*30));
			break;
		default:
			break;
		}
}

#define USAGE 							\
"usage: %s [-?haeFlp] [-b bps] [-B bps] [-f filter expr] [-i interface]    \
\n	    [-o output] [-R seconds] [-r filename] [-s seconds] [interval] \
\n	-?, -h 		- display this help				\
\n	-a 		- accounting mode				\
\n	-b bps		- bandwidth mode, where bps is bits/second	\
\n	-B bps		- dumb bandwidth mode, where bps is bits/second \
\n	-e 		- do not print empty intervals			\
\n	-F	 	- flush stdout after printing each line		\
\n	-f filter expr 	- packet filter expression (like in tcpdump)	\
\n	-i interface	- do live capture on [interface], not from file \
\n	-l		- include linklayer in packet size calc		\
\n	-o output 	- format for the output of stats (see manpage)	\
\n	-p		- non-promiscuous mode when doing live capture	\
\n	-R seconds 	- display time relative to [seconds]		\
\n	-r filename 	- read data from [filename]			\
\n	-s seconds 	- capture only [seconds] long (-1 is infinite)	\
\n									\
\n	interval	- time interval (seconds) for taking samples	\
\n"

int Usage(int r, char *prog) {
	fprintf(stderr, "%s version %s\n", PACKAGE, VERSION);
	fprintf(stderr, USAGE, my_basename(prog));
	return r;
}

void error(char *s) {
	fprintf(stderr, "error: %s\n", s);
	Usage(-1, "tcpstat"); exit(-1);
}

int main(int argc, char **argv) {
	char *filename;
	int ch;

	if (getuid() != geteuid())
		is_setuid = 1;
#ifndef NO_FILEDESC
	if (is_setuid)
		fprintf(stderr, SETUID_WARNING);
#endif /* NO_FILEDESC */

		/* Default promisc, like tcpdump(1) */
	interval = 0.0;
	get_tcp_flags = GET_TCPD_DO_LIVE|GET_TCPD_DO_LIVE_PROMISC;
	filename = NULL;
	my_safe_strcpy(&filterexpr, " ");
	my_safe_strcpy(&outputformat, DEFAULT_FORMAT);

	while ( (ch = getopt(argc, argv, "h?aeFlp1B:b:f:i:o:R:r:s:")) != -1) {
		switch(ch) {
			case 'h':
			case '?':
				return Usage(1, argv[0]);
				break;
			case 'a':
				action = ACTION_ACCOUNT;
				break;
			case 'l':
				get_tcp_flags |= GET_TCPD_COUNT_LINKSIZE;
				break;
			case 'p':
				get_tcp_flags &= ~GET_TCPD_DO_LIVE_PROMISC;
				break;
			case 'B':
			case 'b':
				bandwidth = atof(optarg);
				if (bandwidth <= 0) return Usage(1, argv[0]);
				action = ACTION_BANDWIDTH;
				if (ch == 'b') smart_bandwidth = 1;
				break;
			case 'e':
				empty_intervals = 0;
				break;
			case 'F':
				flush_stdout = 1;
				break;
			case 'f':
				my_safe_strcpy(&filterexpr, optarg);
				break;
			case 'i':
				get_tcp_flags |= GET_TCPD_DO_LIVE;
				my_safe_strcpy(&filename, optarg);
				break;
			case 'o':
				my_safe_strcpy(&outputformat, optarg);
				break;
			case 'R':
				relative_seconds = atof(optarg);
				if (relative_seconds < 0) return Usage(1, argv[0]);
				break;
			case 'r':
				get_tcp_flags &= ~GET_TCPD_DO_LIVE;
				my_safe_strcpy(&filename, optarg);
				break;
			case 's':
				capture_seconds = atof(optarg);
				if (capture_seconds <= 0 &&
					capture_seconds != -1)
					return Usage(1, argv[0]);
				break;
			case '1':
				interval = -1.0;
				break;
			default:
				break;
			}				
		}

	if (interval == 0.0) {
		if ((argc - optind) < 1)
			interval = DEFAULT_INTERVAL;
		else {
			interval = atof(argv[optind]);
			if (interval <= 0 && interval != -1) {
				fprintf(stderr, "error: Bad interval value\n");
				return Usage(1, argv[0]);
				}
			}
		}

		/* Sanity checks */
	if ( ! (get_tcp_flags & (GET_TCPD_DO_LIVE|GET_TCPD_DO_LIVE_PROMISC)) )
		error("-p option not compatible with -r");

		/* If we are doing a limited capture, make sure that
		 * the interval isn't longer than the time that we
		 * are capturing.
		 */
	if (capture_seconds > 0.0 && capture_seconds < interval)
		interval = -1.0;

	if (filename == NULL) {
			/* Default read from interface */
		get_tcp_flags |= GET_TCPD_DO_LIVE;
		my_safe_strcpy(&filename, "auto");
		}
	process_file(filename, 0);
	if (filename) free(filename);
	if (filterexpr) free(filterexpr);
	if (outputformat) free(outputformat);

	return 0;
}
