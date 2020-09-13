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
 * $Id: process.c,v 1.41 2002/06/01 06:42:09 pherman Exp $
 */

#include "tcpstat.h"
#include "snoop.h"

	/* Set alarm in 10 minute (600 seconds) steps
	 * This is necessary, because ualarm() is usually limited:
	 * FreeBSD, Solaris:	2^32/10^6 seconds (71m 35s)
	 * Linux:	??
	 */
#define SECONDS_STEP	600.0

packet_data	pdata;
int		run;
Double		seconds_left;

struct	hook_and_sinker {
	void 	(*hook)(packet_data *, void **);
	void	**args;
	int	proc_flags;
	bpf_u_int32	linktype;
};

void process_catch_alarm(int a) {
	seconds_left -= SECONDS_STEP;
	if (seconds_left <= 0 || a == SIGINT) run = 0;
	else my_alarm((seconds_left > SECONDS_STEP)? SECONDS_STEP : seconds_left);
}

#define MAGIC_SIZE	2
int get_dumpfile_info(char *fname, u_int *df_type) {
	int fd, len;
	u_int magics[MAGIC_SIZE];

	if (df_type == NULL || fname == NULL) return -1;
	fd = open(fname, O_RDONLY);
	if (fd == -1) {
		perror("open()");
		return -1;
		}
	len = (int)read(fd, magics, MAGIC_SIZE*sizeof(u_int) );
	(void)close(fd);
	if (len != MAGIC_SIZE*sizeof(u_int)) {
		fprintf(stderr, "read(): couldn't read file magic\n");
		return -1;
		}
	if (magics[0] == (unsigned int)PCAP_FILE_MAGIC)
		*df_type = PCAP_FILE_MAGIC;
	else if (magics[0] == (unsigned int)PCAP_FILE_MAGIC_RH)
		*df_type = PCAP_FILE_MAGIC_RH;
	else if (magics[0] == (unsigned int)SNOOP_FILE_MAGIC &&
		    magics[1] == (unsigned int)SNOOP_FILE_MAGIC_2)
		*df_type = SNOOP_FILE_MAGIC;
	magics[0] = (unsigned int)ntohl(magics[0]);
	magics[1] = (unsigned int)ntohl(magics[1]);
	if (magics[0] == (unsigned int)PCAP_FILE_MAGIC)
		*df_type = PCAP_FILE_MAGIC;
	else if (magics[0] == (unsigned int)PCAP_FILE_MAGIC_RH)
		*df_type = PCAP_FILE_MAGIC_RH;
	else if (magics[0] == (unsigned int)SNOOP_FILE_MAGIC &&
		    magics[1] == (unsigned int)SNOOP_FILE_MAGIC_2)
		*df_type = SNOOP_FILE_MAGIC;
	return 0;
}

/*
 * snoop2pcap() fills a pcap_pkthdr with informaton from a snoop packet.
 * 	the packet data is luckily the same, so it is just a matter of
 *	getting the header correct.
 */
int snoop2pcap(struct snoop_packet_header *sh, struct pcap_pkthdr *ph) {

	if (sh == NULL || ph == NULL) return -1;
	ph->ts.tv_sec = ntohl(sh->secs);
	ph->ts.tv_usec = ntohl(sh->usecs);

		/* Length of buffer data present */
	ph->caplen = (bpf_u_int32)ntohl(sh->tlen);

		/* Length of buffer data off the wire */
	ph->len = (bpf_u_int32)ntohl(sh->len);

	return 0;
}

void process_pcap(u_char *user, const struct pcap_pkthdr *h, const u_char *p) {
	struct hook_and_sinker	*hs;
	struct ether_header	*ep;
	u_int length = h->caplen, x;
	u_char	*packet;

	hs = (struct hook_and_sinker *) user;
	packet = (u_char *) p;
	ep = (struct ether_header *) p;

	pdata.link_type = 0;
	switch (hs->linktype) {
		case DLT_NULL:
			/* dunno what this is... assume plain IP? */
		pdata.link_type |= LINK_NONE;
		switch (*(int*)packet) {
			case AF_INET:
				pdata.link_type |= LINK_NONE_IP;
				break;
#ifdef INET6
			case AF_INET6:
				pdata.link_type |= LINK_NONE_IP6;
				break;
#endif
			default: break;
			}
		packet += sizeof(int);
		pdata.packet_len = h->len;
		break;

		case DLT_EN10MB:
		packet += sizeof(struct ether_header);
		length -= sizeof(struct ether_header);
			/* XXX: these bcopys are VERY expensive, apparently */
		bcopy(&(ep->ether_shost), &(pdata.ether.ether_shost), sizeof(struct ether_addr));
		bcopy(&(ep->ether_dhost), &(pdata.ether.ether_dhost), sizeof(struct ether_addr));
		pdata.link_type |= LINK_ETHERNET;
		switch (ntohs(ep->ether_type)) {
	        	case ETHERTYPE_IP:
				pdata.link_type |= LINK_ETHERNET_IP;
			 	break;
#ifdef INET6
	        	case ETHERTYPE_IPV6:
				pdata.link_type |= LINK_ETHERNET_IP6;
			 	break;
#endif
	        	case ETHERTYPE_ARP:
				pdata.link_type |= LINK_ETHERNET_ARP;
				break;
	        	case ETHERTYPE_REVARP:
				pdata.link_type |= LINK_ETHERNET_REVARP;
				break;
	        	case ETHERTYPE_IPX:
				pdata.link_type |= LINK_ETHERNET_IPX;
				break;
		/* XXX: Dunno of the following get caught... */
	        	case ETHERTYPE_AT:
				pdata.link_type |= LINK_ETHERNET_AT;
				break;
	        	case ETHERTYPE_AARP:
				pdata.link_type |= LINK_ETHERNET_AARP;
				break;
			default:
        			break;
			}
		pdata.ether.ether_type = ntohs(ep->ether_type);
		pdata.packet_len = h->len;
			/* XXX: this is not exactly correct
				because IXP, AT, etc. don't have
				the same linksize
			 */
		if (!(hs->proc_flags & GET_TCPD_COUNT_LINKSIZE) )
		    pdata.packet_len -= ETHER_HDR_LEN;
		break;
		case DLT_PPP:
			pdata.link_type |= LINK_PPP;

		x = (unsigned int)((packet[2]<<8) | packet[3]);
		switch (x) {
			case 0x0021: pdata.link_type |= LINK_PPP_IP; break;
			case 0x8021: pdata.link_type |= LINK_PPP_IPCP; break;
#ifdef INET6
			case 0x0057: pdata.link_type |= LINK_PPP_IP6; break;
			case 0x8057: pdata.link_type |= LINK_PPP_IPCP6; break;
#endif
			case 0x80fd: pdata.link_type |= LINK_PPP_CCP; break;
			case 0xc021: pdata.link_type |= LINK_PPP_LCP; break;
			case 0xc023: pdata.link_type |= LINK_PPP_PAP; break;
			case 0xc223: pdata.link_type |= LINK_PPP_CHAP; break;
			default: pdata.link_type |= LINK_PPP_OTHER; break;
			}
		packet += PPP_HDRLEN;
		length -= PPP_HDRLEN;
		pdata.packet_len = h->len;
		if (!(hs->proc_flags & GET_TCPD_COUNT_LINKSIZE) )
		    pdata.packet_len -= PPP_HDRLEN;
		break;
		default:
			/* XXX: Assume then plain IP? */
#if DEBUG
		printf("Unknown Link Type: %X\n", hs->linktype);
#endif
		pdata.packet_len = h->len;
		break;
		}

	length = (length<PAK_SIZ)? length : PAK_SIZ;
	bcopy((void *)&(h->ts), &(pdata.timestamp), sizeof(struct timeval) );
	bcopy(packet, &(pdata.data.raw), length);

	pdata.buffer_len = length;

	hs->hook(&pdata, hs->args);
}

/*
 * get_snoop_data() reads a snoop file, converts it to pcap format, and
 *   calls a user function pointing to the data
 *
 * XXX: filter is not used.  capture_seconds also isn't, but snoop is
 *	always read from a file.
 */
int get_snoop_data(char *fname, char *filter, int flags,
	Double capture_seconds, void (*hook)(packet_data *, void **),
	void **args) {

	u_char *packet;
	int fd, len, blen, ret = 0;
	struct snoop_file_header	fh;
	struct snoop_packet_header	ph;
	struct hook_and_sinker		hs;
	struct pcap_pkthdr		pcap_hdr;

	if (flags & GET_TCPD_DO_LIVE) {
		fprintf(stderr, "Read live snoop data?!?  This error should not happen.\n");
		return -1;
		}
	if (fname == NULL) return -1;

	fd = open(fname, O_RDONLY);
	if (fd == -1) {
		perror("open()");
		return -1;
		}

	len = read(fd, &fh, sizeof(fh) );
	if (len != (int)sizeof(fh)) {
		fprintf(stderr, "get_snoop_data: Can't read file header\n");
		(void)close(fd);
		return -1;
		}

	hs.hook = hook;
	hs.args = args;
	hs.proc_flags = flags;

	switch (ntohl(fh.linktype)) {
		case SNOOP_DL_ETHER:
			hs.linktype = DLT_EN10MB;
			break;
		default:
			fprintf(stderr, "get_snoop_data: No support for this link type (yet?)\n");
			(void)close(fd);
			return -1;
			/* UNREACHED */
			break;
		}

			/* Main Loop */
	while ( (len = (int)read(fd, &ph, sizeof(ph))) != 0) {
		if (len != (int)sizeof(ph)) {
			fprintf(stderr, "get_snoop_data: Can't read packet header\n");
			ret = -1; break;
			}

		blen = ntohl(ph.blen) - sizeof(ph);

		packet = (u_char *) malloc(blen * sizeof(u_char));
		if (packet == NULL) return -1;

		len = (int)read(fd, packet, blen);
		if (len != blen) {
			fprintf(stderr, "get_snoop_data: Can't read packet data\n");
			ret = -1; free(packet); break;
			}

		(void)snoop2pcap(&ph, &pcap_hdr);
		process_pcap((u_char *)&hs, &pcap_hdr, packet);

		free(packet);
		}

	(void)close(fd);
	return ret;
}

/*
 * get_pcap_data() is a hook for pcap_loop and
 *   calls a user function pointing to the data
 */
int get_pcap_data(char *fname, char *filter, int flags,
	Double capture_seconds, void (*hook)(packet_data *, void **),
	void **args) {

	pcap_t	*pd;
	int	i;
	char	ebuf[PCAP_ERRBUF_SIZE];
	struct	bpf_program bpf_prog;
	struct	hook_and_sinker	hs;

#define SNAPLEN	68	/* XXX: Doesn't belong here */
	if (flags & GET_TCPD_DO_LIVE) {
		if (fname == NULL || 
		 (strlen(fname) == strlen("auto") &&
			strncmp(fname, "auto", 4) == 0)
			) {
			fname = pcap_lookupdev(ebuf);
			if (fname == NULL) {
				fprintf(stderr, "pcap_lookupdev(): %s\n", ebuf);
				return -1;
				}
			fprintf(stderr, "Listening on %s\n", fname);
			}
		pd = pcap_open_live(fname, SNAPLEN,
			flags & GET_TCPD_DO_LIVE_PROMISC, 100, ebuf);
		}
		
	else pd = pcap_open_offline(fname, ebuf);
	if (pd == NULL) {
		fprintf(stderr, "pcap_open(): %s\n", ebuf);
		return -1;
		}
	if (pcap_compile(pd, &bpf_prog, filter, 1, 0) < 0) {
		fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(pd));
		return -1;
		}
	if (pcap_setfilter(pd, &bpf_prog) < 0) {
		fprintf(stderr, "pcap_setfilter(): %s\n", pcap_geterr(pd));
		return -1;
		}
	hs.hook = hook;
	hs.args = args;
	hs.proc_flags = flags;
	hs.linktype = (bpf_u_int32)pcap_datalink(pd);

	run = 1;
	seconds_left = capture_seconds;

	/* only catch SIGINT when doing live reads, otherwise just exit */
	if (flags & GET_TCPD_DO_LIVE)
		(void)signal(SIGINT, process_catch_alarm);

	if (capture_seconds > 0.0 && flags & GET_TCPD_DO_LIVE) {
		(void)signal(SIGALRM, process_catch_alarm);
		my_alarm((seconds_left > SECONDS_STEP)? SECONDS_STEP : seconds_left);
		}
	while (run) {
		i = pcap_dispatch(pd, -1, process_pcap, (u_char *)&hs);
		if (i == 0 && ! (flags & GET_TCPD_DO_LIVE)) run = 0;
		if (i == -1) {
			fprintf(stderr, "pcap_dispatch(): %s\n", pcap_geterr(pd) );
			run = 0;
			}
		}
	pcap_close(pd);
	return 0;
}

/*
 * get_dump_data() is a hook for pcap_loop and
 *   calls a user function pointing to the data
 */
int get_dump_data(char *fname, char *filter, int flags,
	Double capture_seconds, void (*hook)(packet_data *, void **),
	void **args) {
	u_int df_type = 0;

	df_type = PCAP_FILE_MAGIC;	/* Default to pcap format */

	if ( (strlen(fname) != 1 || *fname != '-') &&
		!(flags & GET_TCPD_DO_LIVE) ) {
			/* We are not reading data from stdin, and we
			 * are not doing a live dump, so we need to check
			 * to see if the file to be read is a regular file
			 * (or link.)  The reason for this is we can't
			 * lseek() on a named pipe.
			 */
#ifdef HAVE_SYS_STAT_H
		struct stat fst;
		if (stat(fname, &fst) == -1) {	/* Try to get stat() of file */
			perror("stat()");
			return -1;
			}
		if (fst.st_mode & (S_IFREG | S_IFLNK) ) {
			/* Reading a file */
			if (get_dumpfile_info(fname, &df_type)) return -1;
			}

#else			/* No idea, just guess */
		if (get_dumpfile_info(fname, &df_type)) return -1;
#endif

		}
	switch(df_type) {
		case PCAP_FILE_MAGIC:
		case PCAP_FILE_MAGIC_RH:	/* Try RedHat format as well. */
			return get_pcap_data(fname, filter, flags,
				capture_seconds, hook, args);
			/* NOTREACHED */
			break;
		case SNOOP_FILE_MAGIC:
			return get_snoop_data(fname, filter, flags,
				capture_seconds, hook, args);
			/* NOTREACHED */
			break;
		default:
			fprintf(stderr, "Sorry, Unknown file format\n");
			return -1;
			/* NOTREACHED */
			break;
		}
		/* Never reached */
	return 0;
}
