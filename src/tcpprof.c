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
 * $Id: tcpprof.c,v 1.7 2002/01/19 04:31:37 pherman Exp $
 */

#include "tcpprof.h"

char	numbers_only		= 0;
char	filterexpr[BUF_SIZ]	= "";
char	registered_only		= 0;
char	src_dest_split		= 0;
int	ports_to_show		= IPPORT_RESERVED;
int	lines_to_show		= -1;

#define USAGE 								\
"Usage: %s [-?hnpR] [-f filter expr] [-i interface] [-P port]		\
\n		[-r file] [-s seconds] [-S letters] [-t lines]		\
\n	-?, -h 		- display this help				\
\n	-d		- show source/dest statistics			\
\n	-f filter expr	- tcpdump(1) filter expression			\
\n	-i interface	- do live capture on [interface], not from file \
\n	-n		- don't resolve network numbers			\
\n	-p		- non-promiscuous mode when doing live capture	\
\n	-P port		- ignore port numbers >= port			\
\n	-r file		- read tcpdump data from file			\
\n	-R		- display only registered ports			\
\n	-s seconds	- capture only [seconds] long			\
\n	-S letters	- collect stats					\
\n		a		- collect ALL stats			\
\n		l		- collect link stats			\
\n		i		- collect ip stats			\
\n		p		- collect port stats			\
\n		h		- collect host stats			\
\n		n		- collect network stats			\
\n	-t lines	- show at most [lines] lines for each stat	\
\n									\
\nExample: %s -S ph -r data.dump					\
\n	Displays port and host statistics from the file 'data.dump'	\
\n"

void my_hook(packet_data *pd, void **args) {
	u_int		*types;

	types = (u_int *) *args++;
	stats_insert(pd, *types);
}

/*
 * process_file() takes the output of tcpdump, saves packets, and creates
 * statistics
 */
void process_file(char *fname, u_int s_types, int flags, Double capture_seconds) {
	void		*argv[1];

	stats_initdb(s_types);

	argv[0] = (void *) &s_types;
	if (get_dump_data(fname, filterexpr, flags, capture_seconds, my_hook, argv) == 0)
		show_results(s_types);

	stats_closedb();
}

u_int parse_stats_types(char *in) {
	u_int ret = 0;
	while (*in) {
		if (*in == 'l' || *in == 'a' ) ret |= TYPE_LINK;
		if (*in == 'i' || *in == 'a' ) ret |= TYPE_IP_PROTO;
		if (*in == 'p' || *in == 'a' ) ret |= TYPE_PORT;
		if (*in == 'h' || *in == 'a' ) ret |= TYPE_HOST;
		if (*in == 'n' || *in == 'a' ) ret |= TYPE_NET;
		in++;
		}
	return ret;
}

int Usage(int r, char *prog) {
	fprintf(stderr, USAGE, my_basename(prog), prog);
	return r;
}

void error(char *s) {
	fprintf(stderr, "error: %s\n", s);
	Usage(-1, "tcpprof"); exit(-1);
}

int main(int argc, char **argv) {
	char	filename[BUF_SIZ];
	u_int	stats_types = TYPE_ALL;
	int	flags = GET_TCPD_COUNT_LINKSIZE | GET_TCPD_DO_LIVE_PROMISC;
	int	ch;
	Double	capture_seconds = -1.0;

	filename[0] = 0;
	while ( (ch = getopt(argc, argv, "h?ndpP:Rf:i:s:S:r:t:")) != -1) {
		switch(ch) {
			case 'h':
			case '?':
				return Usage(1, argv[0]);
				break;
			case 'd':
				src_dest_split = 1;
				break;
			case 'f':
				strncpy(filterexpr, optarg, BUF_SIZ);
				break;
			case 'i':
				strncpy(filename, optarg, BUF_SIZ);
				flags |= GET_TCPD_DO_LIVE;
				break;
			case 'r':
				strncpy(filename, optarg, BUF_SIZ);
				flags &= ~GET_TCPD_DO_LIVE;
				break;
			case 'n':
				numbers_only = 1;
				break;
			case 'p':
				flags &= ~GET_TCPD_DO_LIVE_PROMISC;
				break;
			case 'P':
				ports_to_show = (int) strtol(optarg, NULL, 10);
				registered_only = 1;
				break;
			case 'R':
				registered_only = 1;
				break;
			case 's':
				capture_seconds = atof(optarg);
				if (capture_seconds <= 0.0 &&
				    capture_seconds != -1.0)
					return Usage(1, argv[0]);
				break;
			case 'S':
				stats_types |= parse_stats_types(optarg);
				break;
			case 't':
				lines_to_show = (int) strtol(optarg, NULL, 10);
				break;
			default:
				break;
			}				
		}

	if (filename == NULL || strlen(filename) < 1) {
		strncpy(filename, "auto", BUF_SIZ);
		flags |= GET_TCPD_DO_LIVE;
		}

	process_file(filename, stats_types, flags, capture_seconds);

	return 0;
}
