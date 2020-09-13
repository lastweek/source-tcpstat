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
 * $Id: utils.c,v 1.23 2002/01/02 21:05:55 pherman Exp $
 */

#include "tcpstat.h"

char str[BUF_SIZ];

int is_ethernetarp_packet(packet_data *p) {
	return ( (p->link_type & LINK_ETHERNET) &&
		 (p->ether.ether_type == ETHERTYPE_ARP)
			);	/* Requires ethernet.h */
}

int is_ip_packet(packet_data *p) {
	return ((p->link_type & LINK_NONE_OTHER) == GENERIC_LINK_IP);
}

#ifdef INET6
int is_ip6_packet(packet_data *p) {
	return ((p->link_type & LINK_NONE_OTHER) == GENERIC_LINK_IP6);
}
#endif

unsigned char get_ip_proto(packet_data *p) {
	struct ip *ip;

	if (is_ip_packet(p)) {
	   ip = &(p->data.ip.hdr);
	   return ( ip->ip_p );
	   }
#ifdef INET6
	else if (is_ip6_packet(p)) {
	   struct ip6_hdr *ip6;
	   ip6 = &(p->data.ip6.hdr);
	   return ( ip6->ip6_nxt );
	   }
#endif
	return 0;
}

int is_ip_tcp_packet(packet_data *p) {
	return ( get_ip_proto(p) == IPPROTO_TCP );
}

int is_ip_udp_packet(packet_data *p) {
	return ( get_ip_proto(p) == IPPROTO_UDP );
}

int is_ip_icmp_packet(packet_data *p) {
	return ( get_ip_proto(p) == IPPROTO_ICMP
#ifdef INET6
		|| get_ip_proto(p) == IPPROTO_ICMPV6
#endif
		);
}

char *my_basename(char *p) {
	char *s;

	s = p;
	if (!*s || strlen(s) < 2) return p;

	for (s += strlen(p); s>p && *s != '/'; s--) continue;
	return (*s == '/')? s+1 : s;
}

u_char count_1bits(u_int x) {
	u_char r = 0;
	int i;

	for (i=0; i<8*(int)sizeof(x); i++)
		if ( (x>>i) & 0x1 ) r++;
	return r;
}

char *my_get_port(u_short port, int n_only) {
	struct servent *srvent;
	if (n_only) {
		snprintf(str, BUF_SIZ, "%u", port);
		}
	else {
	        srvent = getservbyport(htons(port), NULL);
		if (srvent == NULL) snprintf(str, BUF_SIZ, "%u", port);
		else	snprintf(str, BUF_SIZ, "%s (%u)", srvent->s_name, port);
		}
	return str;
}

char *my_get_proto(u_short proto, int n_only) {
	struct protoent *ip_prot;

	if (n_only) {
		snprintf(str, BUF_SIZ, "%u", proto);
		}
	else {
	        ip_prot = getprotobynumber(proto);
		if (ip_prot == NULL) snprintf(str, BUF_SIZ, "%u", proto);
		else	snprintf(str, BUF_SIZ, "%s", ip_prot->p_name);
		}
	return str;
}

	/* XXX: Does this define belong here? */
#define MAX_STRCPY	32768

char *my_safe_strcpy(char **dst, const char *src) {
	size_t n;

	n = strlen(src)*sizeof(char);
	if (n<1) n = 1;
	if (n>MAX_STRCPY) n = MAX_STRCPY;

	if (*dst != NULL) free(*dst);
	*dst = (char *)malloc(n+1);
	if (*dst == NULL) {
		perror("my_safe_strcpy()");
		exit(-1);
		}
	**dst = '\0';
	return strncat(*dst, src, n);
}

void my_alarm(Double seconds) {
#ifdef HAVE_UALARM
	ualarm( (u_int) (seconds*1e6 + 0.5), 0);
#else
	alarm( (u_int) (seconds));
#endif /* HAVE_UALARM */
}

#ifndef HAVE_INET_NTOP
char *inet_ntop(int af, void *src, char *dst, int n) {
	int i;
	unsigned char *ui, u;
	char c[2];

	if (dst == NULL || n<1) return NULL;
	dst[0] = '\0';
	switch (af) {
		case AF_INET:		/* Broken, use inet_ntoa() instead */
			break;
# ifdef INET6
		case AF_INET6:
			c[1] = 0;
			for (i=0, ui = (unsigned char *)src; i<16; i++, ui++) {
				u = (*ui >> 4) & 0x0f;
				c[0] = (u < 0x0A)? u + '0' : (u-0x0A) + 'A';
				strcat(dst, c);
				u = *ui & 0x0f;
				c[0] = (u < 0x0A)? u + '0' : (u-0x0A) + 'A';
				strcat(dst, c);
				}
			break;
# endif /* INET6 */
		default:
			break;
		}
	return dst;
}
#endif /* HAVE_INET_NTOP */
