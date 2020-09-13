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
 * $Id: dump.c,v 1.14 2002/09/18 21:00:29 pherman Exp $
 */

/**********************************************************
 * Example of how to use the library included
 * with this program
 **********************************************************/
#include "packetdump.h"

/* GLOBALS */
char filterexpr[BUF_SIZ]	= "";
int	get_tcp_flags		= 0;
int	what_to_show		= 0;
int	packet_number		= 0;

void my_hook(packet_data *pd, void **args) {
	printf("PACKET NUMBER: %d\n", ++packet_number);
	print_packet(pd, what_to_show);
	printf("-------------------\n");
}

/*
 * process_file() takes the output of tcpdump, saves packets, and displays
 * statistics
 */
void process_file(char *fname, u_int unused) {
        get_dump_data(fname, filterexpr, get_tcp_flags,
		-1.0, my_hook, NULL);
}

int parse_show_types(char *in) {
	int ret = 0;
	while (*in) {
		if (*in == 'b' || *in == 'a' ) ret |= PP_SHOW_BASICINFO;
		if (*in == 'l' || *in == 'a' ) ret |= PP_SHOW_LINKLAYER;
		if (*in == 'i' || *in == 'a' ) ret |= PP_SHOW_IPHEADER;
		if (*in == 'c' || *in == 'a' ) ret |= PP_SHOW_PACKETCONTENT; 
		if (*in == 't' || *in == 'a' )
			ret |=    PP_SHOW_TCPHEADER
				| PP_SHOW_UDPHEADER
				| PP_SHOW_ICMPHEADER;
		in++;
	}
	return ret;
}

#define USAGE 							\
"Usage: %s [-?hls] [-f filter expr] [-r file] [-s letters]		\
\n	-?, -h 		- display this help				\
\n	-f filter expr 	- filter expression to pass to tcpdump		\
\n	-l		- include link layer in packet size calc	\
\n	-r file 	- file to read data from			\
\n	-s letters	- what to show from packet, where letters is any of: \
\n		a		- everything				\
\n		b		- basic info				\
\n		l		- link info				\
\n		i		- IP info				\
\n		t		- TCP/UDP/ICMP info			\
\n		c		- packet content			\
\n"

int Usage(int r, char *prog) {
	fprintf(stderr, USAGE, my_basename(prog)); return r;
}

void error(char *s) {
	fprintf(stderr, "error: %s\n", s);
	Usage(-1, "packetdump"); exit(-1);
}

int main(int argc, char **argv) {
	char filename[BUF_SIZ];
	int ch;

	*filename = 0;
	while ( (ch = getopt(argc, argv, "h?lf:r:s:")) != -1) {
		switch(ch) {
			case 'h':
			case '?':
				return Usage(1, argv[0]);
				break;
			case 'l':
				get_tcp_flags |= GET_TCPD_COUNT_LINKSIZE;
				break;
			case 'f':
				strncpy(filterexpr, optarg, BUF_SIZ);
				break;
			case 'r':
				strncpy(filename, optarg, BUF_SIZ);
				break;
			case 's':
				what_to_show |= parse_show_types(optarg);
				break;
			default:
				return Usage(1, argv[0]);
				break;
			}				
		}

	if (*filename == 0) error("must specify filename");

	process_file(filename, 0);

	return 0;
}
