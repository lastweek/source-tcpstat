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
 * $Id: catpcap.c,v 1.6 2002/09/18 21:00:29 pherman Exp $
 */

#include "tcpstat.h"

#if 0
#ifdef WORDS_BIGENDIAN
# define LAST_CHAR(x)	( (x) >> 8 )
# define SWAPEM(x)	( (x) )
#else
# define LAST_CHAR(x)	( (x) & 0x00ff )
# define SWAPEM(x)	( (((x) << 8)&0xff00) | (((x) >> 8)&0x00ff))
#endif
#endif

#define SHOW_HIGH_BIT	0

/* GLOBALS */
char filterexpr[BUF_SIZ]	= "";
int p_number			= 1;

char char_conv(char c) {
	if (isgraph(c)) return c;
	if (c == ' ') return c;
	if ((u_char)c > 0xa1 && SHOW_HIGH_BIT) return c;
	return '.';
}

void proc_pcap(u_char *user, const struct pcap_pkthdr *h, const u_char *p) {
	u_int length = h->caplen, i, j, k, step;
	u_char *r, *s;
	char c;

	r = (u_char *)p;
	s = (u_char *)p;
	step = 22;
	printf("%u: %lu.%.6lu, caplen %u, len %u\n",
		p_number++,
		(long unsigned int) h->ts.tv_sec,
		(long unsigned int) h->ts.tv_usec,
		h->caplen, h->len
		);
	for (i=0; i<length; ) {
		printf(" ");
		for (j=0; j<step && (j+i)<length;) {
			printf("%.2X", *r++);
			j++;
			if ( (j+i) == length ) { 
				printf("   "); j++; break; }
			printf("%.2X ", *r++);
			j++;
			}
		for (k=j; k<step; k++, k++) printf("     ");
		printf(" ");

		for (j=0; j<step && (j+i)<length; j++) {
			c = *p++;
			printf("%c", char_conv(c));
			}
		printf("\n");
		i += j;
		}
	printf("\n");
}
/*
 * process_file() takes the output of tcpdump, saves packets, and displays
 * statistics
 */
void process_file(char *fname, u_int unused) {
	int run = 1, i;
	pcap_t	*pd;
	char	ebuf[PCAP_ERRBUF_SIZE];
	struct bpf_program	bpf_prog;

	pd = pcap_open_offline(fname, ebuf);
	if (pd == NULL) {
		fprintf(stderr, "pcap_open(): %s\n", ebuf);
		return;
		}
	if (pcap_compile(pd, &bpf_prog, filterexpr, 1, 0) < 0) {
		fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(pd));
		return;
		}
	if (pcap_setfilter(pd, &bpf_prog) < 0) {
		fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(pd));
		return;
		}
	printf("Pcap Version %d.%d,  Datalink 0x%.8X,  Snapshot %d, %s swapped\n",
		pcap_major_version(pd), pcap_minor_version(pd),
		pcap_datalink(pd), pcap_snapshot(pd),
		(pcap_is_swapped(pd))? "" : "not"
		);
	printf("-------------------------------------------------\n");
	while (run) {
		i = pcap_dispatch(pd, -1, proc_pcap, NULL);
		if (i == 0) run = 0;
		if (i == -1) {
			fprintf(stderr, "pcap_dispatch(): %s\n", pcap_geterr(pd));
			run = 0;
			}
		}
	pcap_close(pd);
}

#define USAGE 							\
"Usage: %s [-?heBLITC] [-f filter expr] [-r file]		\
\n	-?, -h 		- display this help			\
\n	-f filter expr 	- filter expression to pass to tcpdump	\
\n	-r file 	- file to read data from		\
\n"

int Usage(int r, char *prog) {
	fprintf(stderr, USAGE, prog); return r;
}

void error(char *s) {
	fprintf(stderr, "error: %s\n", s);
	Usage(-1, "catpcap"); exit(-1);
}

int main(int argc, char **argv) {
	char filename[BUF_SIZ];
	int ch;

	*filename = 0;
	while ( (ch = getopt(argc, argv, "h?f:r:")) != -1) {
		switch(ch) {
			case 'h':
			case '?':
				return Usage(1, argv[0]);
				break;
			case 'f':
				strncpy(filterexpr, optarg, BUF_SIZ);
				break;
			case 'r':
				strncpy(filename, optarg, BUF_SIZ);
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
