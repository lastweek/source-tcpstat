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
 * $Id: tcpstat.h,v 1.41 2002/06/01 06:42:08 pherman Exp $
 */

#ifndef TCPSTAT_TCPSTAT_H
#define TCPSTAT_TCPSTAT_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#else  /* Hmmm, try to wing it */
# ifdef __linux__
# define _BSD_SOURCE
# endif
#endif /* HAVE_CONFIG_H */

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <stdio.h>		/* printf() */
#include <unistd.h>		/* fork(), execlp() */
#include <stdlib.h>		/* free(), malloc() */
#include <string.h>		/* bzero() */
#include <math.h>		/* sqrt() */
#include <ctype.h>		/* tolower */

#include <sys/time.h>		/* struct timeval */
#include <sys/wait.h>		/* waitpid() */
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>		/* stat() */
#endif

#include <sys/socket.h>		/* needed by INET stuff (sockaddr) */
#include <netinet/in.h>		/* needed by INET stuff (in_addr) */
#include <netinet/in_systm.h>	/* needed by INET stuff (n_long) */

#ifdef HAVE_NETINET_IP6_H
# ifdef AIX_STRANGENESS
#  define STEVENS_API		/* this gives us BSD style ip6hdr */
#  define ip6_hdr	ip6hdr
# endif
# include <netinet/ip6.h>	/* IPv6 structs and constats */
# include <netinet/icmp6.h>	/* IPv6 ICMP stuff */
# ifndef INET6
#  define INET6			/* Force INET6 code */
# endif
# ifdef TRU64_STRANGENESS
#  ifndef ip6_vfc
#   define ip6_vfc ip6_vcf	/* Is this a Tru64 typo? */
#  endif
# endif
#endif

#ifdef HAVE_NET_ETHERNET_H
# include <net/ethernet.h>	/* struct ether_header */
#else
# if defined(HAVE_NETINET_IF_ETHER_H) && defined(AIX_STRANGENESS)
#  include "netinet/if_ether.h"
# else
#  include "ethernet_stub.h"	/* Hope this works... */
# endif
#endif

#ifndef ETHERTYPE_IPX
# define ETHERTYPE_IPX	0x8137		/* IPX Protocol */
#endif
#ifndef ETHERTYPE_AT
# define ETHERTYPE_AT    0x809B          /* AppleTalk protocol */
# define ETHERTYPE_AARP  0x80F3          /* AppleTalk ARP */
#endif
#ifndef ETHERTYPE_IPV6
# define ETHERTYPE_IPV6  0x86dd		/* IPv6 */
#endif
#ifndef ETHER_HDR_LEN
# define ETHER_HDR_LEN	14		/* Just in case... */
#endif

#ifdef HAVE_NET_IF_H
# include <net/if.h>		/* struct ifnet */
#endif
#include <net/if_arp.h>		/* struct arp_hdr */
#include <netinet/ip.h>		/* struct ip */
#include <netinet/tcp.h>	/* struct tcphdr */
#include <netinet/udp.h>	/* struct udphdr */
#include <netinet/ip_icmp.h>	/* struct icmp */
#include <arpa/inet.h>		/* inet_ntoa() */
#include <netdb.h>		/* getprotobynumber */
#include <pcap.h>		/* pcap_*() */

#include <signal.h>

#ifdef HAVE_STRINGS_H
# include <strings.h>		/* Solaris bzero/bcopy/etc... */
#endif

#ifdef HAVE_NET_PPP_DEFS_H
# include <net/ppp_defs.h>
#else
# define PPP_HDRLEN	4
#endif /* HAVE_NET_PPP_DEFS_H */

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#else
# define O_RDONLY        0x0000          /* open for reading only */
#endif /* HAVE_FCNTL_H */

#ifndef HAVE_PERROR
#define perror(x)	{ fprintf(stderr, "Error: %s\n", x); }
#endif /* !HAVE_PERROR */

#ifndef HAVE_SNPRINTF
# ifdef __GNUC__
#  define snprintf(a, b, c...)		sprintf(a, ## c)
# else
#  define snprintf(a, b, c, d)		sprintf(a, c, d)
# endif /* __GNUC__ */
#endif /* !HAVE_SNPRINTF */

#define BUF_SIZ		4096		/* General string buffer size */
#define PAK_SIZ		32768
#define Double		double		/* FP accuracy */

/*
 * Magic numbers for various dump files
 */
#define PCAP_FILE_MAGIC		0xa1b2c3d4	/* first 4 bytes of PCAP file */
#define PCAP_FILE_MAGIC_RH	0xa1b2cd34	/* proprietary RedHat PCAP file */
#define SNOOP_FILE_MAGIC	0x736e6f6f	/* "snoo" */
#define SNOOP_FILE_MAGIC_2	0x70000000	/* "p\0\0\0 */

	/* Orthogonal Link types in struct packet_data */
#define LINK_NONE	0x0001
#define LINK_ETHERNET	0x0002
#define LINK_PPP	0x0004

#define GENERIC_LINK_IP		0x0100
#define GENERIC_LINK_IP6	0x0200
#define GENERIC_LINK_OTHER	0xff00

	/* supported LINK_NONE types */
#define LINK_NONE_IP		0x0100
#define LINK_NONE_IP6		0x0200
#define LINK_NONE_OTHER		0xff00

	/* supported LINK_ETHERNET types */
#define LINK_ETHERNET_IP	0x0100		/* Plain old IP */
#define LINK_ETHERNET_IP6	0x0200		/* New IPv6 */
#define LINK_ETHERNET_ARP	0x0300		/* (A)ddress (R)esolution (P)rotocol */
#define LINK_ETHERNET_REVARP	0x0400		/* Reverse ARP */
#define LINK_ETHERNET_IPX	0x0500		/* IPX */
#define LINK_ETHERNET_AT	0x0600		/* Appletalk */
#define LINK_ETHERNET_AARP	0x0700		/* Appletalk ARP */
#define LINK_ETHERNET_OTHER	0xff00

	/* supported LINK_PPP types */
#define LINK_PPP_IP		0x0100
#define LINK_PPP_IP6		0x0200
#define LINK_PPP_IPCP		0x0300
#define LINK_PPP_IPCP6		0x0400
#define LINK_PPP_CCP		0x0500
#define LINK_PPP_LCP		0x0600
#define LINK_PPP_PAP		0x0700
#define LINK_PPP_CHAP		0x0800
#define LINK_PPP_OTHER		0xff00

	/* in get_dump_data, flags on how to operate */
#define GET_TCPD_COUNT_LINKSIZE		0x01
#define GET_TCPD_DO_LIVE		0x02
#define GET_TCPD_DO_LIVE_PROMISC	0x04

typedef struct ip_packet {
	struct ip	hdr;
	union {
		struct tcphdr	tcphdr;
		struct udphdr	udphdr;
		struct icmp	icmp;
	} body;
} ip_packet;

#ifdef INET6
typedef struct ip6_packet {
	struct ip6_hdr	hdr;
	union {
		struct tcphdr	tcphdr;
		struct udphdr	udphdr;
		struct icmp6_hdr icmp6hdr;
	} body;
} ip6_packet;
#endif

typedef struct packet_data {
	struct timeval		timestamp;
	u_int			packet_len;
	u_int			buffer_len;
	u_int			link_type;
	struct ether_header	ether;
	union {
		struct arphdr		arp;
		struct ip_packet	ip;
#ifdef INET6
		struct ip6_packet	ip6;
#endif
		u_char			raw[PAK_SIZ];
	} data;
} packet_data;

/************** Prototypes **************/

/* process.c protos */
int  get_dump_data(char *fname, char *filter, int flags,
        Double capture_seconds, void (*hook)(packet_data *, void **),
	void **args);

/* print_packet.c protos */
void print_packet(packet_data *p, int what_to_print);

/* utils.c protos */
int is_ethernetarp_packet(packet_data *p);
int is_ip_packet(packet_data *p);
unsigned char get_ip_proto(packet_data *p);
int is_ip_tcp_packet(packet_data *p);
int is_ip_udp_packet(packet_data *p);
int is_ip_icmp_packet(packet_data *p);
#ifdef INET6
int is_ip6_packet(packet_data *p);
#endif
char *my_basename(char *p);
char *my_get_port(u_short port, int n_only);
char *my_get_proto(u_short proto, int n_only);
char *my_safe_strcpy(char **dst, const char *src);
void my_alarm(Double seconds);
u_char count_1bits(u_int x);

#ifndef HAVE_INET_NTOP
char *inet_ntop(int af, void *src, char *dst, int n);
#endif /* HAVE_INET_NTOP */

#endif /* TCPSTAT_TCPSTAT_H */

/**************** END *****************/
