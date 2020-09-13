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
 * $Id: print_packet.c,v 1.29 2002/08/12 17:47:24 pherman Exp $
 */

#include "tcpstat.h"
#include "packetdump.h"

char gstr[8192];

void print_arp_header(struct arphdr *arp);
void print_ip_header(struct ip *ip);
void print_tcp_header(struct tcphdr *tcp, unsigned int len, int wtp);
void print_udp_header(struct udphdr *udp, unsigned int len, int wtp);
void print_icmp_header(struct icmp *icmp, unsigned int len, int wtp);
#ifdef INET6
void print_ip6_header(struct ip6_hdr *ip);
void print_icmp6_header(struct icmp6_hdr *icmp6, unsigned int len, int wtp);
#endif

char *my_charconv(char c) {
	char *s;
	gstr[0] = '\0';

	s = gstr;
	if (isgraph((int)c)) *s++ = c;
	else if (c == ' ') *s++ = c;
/*	else if (c == '\n') { *s++ = '\\'; *s++ = 'n'; } */
	else if (c == '\n' || c == '\r') { *s++ = c; }
/*	else if (c == '\r') { *s++ = '\\'; *s++ = 'r'; } */
	else *s++ = '.';
	*s = '\0';
	return gstr;
}


void print_packet(packet_data *p, int what_to_print) {
	struct ip	*ip;
	struct tcphdr	*tcp;
	struct udphdr	*udp;
	struct icmp	*icmp;
#ifdef INET6
	struct ip6_hdr	*ip6;
	struct icmp6_hdr *icmp6;
#endif

	if (what_to_print & PP_SHOW_BASICINFO) {
		printf("PACKET SIZE: %u", p->packet_len);
		if (p->packet_len != p->buffer_len)
			printf(", (BUFFER SIZE: %u)", p->buffer_len);
		printf("\n");
		}

	if (what_to_print & PP_SHOW_LINKLAYER) {
		if (p->ether.ether_type == ETHERTYPE_ARP) {
			print_arp_header(&(p->data.arp));
			printf("---------------------------\n");
			return;
			}
		}
	if ((p->link_type & GENERIC_LINK_OTHER) != GENERIC_LINK_IP 
#ifdef INET6
		&& (p->link_type & GENERIC_LINK_OTHER) != GENERIC_LINK_IP6
#endif
		)
		return;
	/* OK, it's an IP Packet */

	ip = &(p->data.ip.hdr);
	tcp= &(p->data.ip.body.tcphdr);
	udp= &(p->data.ip.body.udphdr);
	icmp= &(p->data.ip.body.icmp);
#ifdef INET6
	ip6 = &(p->data.ip6.hdr);
	tcp= &(p->data.ip6.body.tcphdr);
	udp= &(p->data.ip6.body.udphdr);
	icmp6= &(p->data.ip6.body.icmp6hdr);
#endif

	if (what_to_print & PP_SHOW_IPHEADER) {
		if (is_ip_packet(p)) print_ip_header(ip);
#ifdef INET6
		if (is_ip6_packet(p)) print_ip6_header(ip6);
#endif
		}
	p->buffer_len -= sizeof(struct ip);
	switch (get_ip_proto(p)) {
		case IPPROTO_TCP:
			print_tcp_header(tcp, p->buffer_len, what_to_print);
			break;
		case IPPROTO_UDP:
			print_udp_header(udp, p->buffer_len, what_to_print);
			break;
		case IPPROTO_ICMP:
			print_icmp_header(icmp, p->buffer_len, what_to_print);
			break;
#ifdef INET6
		case IPPROTO_ICMPV6:
			print_icmp6_header(icmp6, p->buffer_len, what_to_print);
			break;
#endif
		default:
			printf("UNKNOWN IP PROTOCOL! (0x%.4X)\n", (unsigned int)get_ip_proto(p));
			break;
		}
}

void print_arp_header(struct arphdr *arp) {
		printf("ARP PACKET:\n");
		printf("\thrd=%u pro=%u hln=%u plen=%u op=%u",
			(unsigned int)htons(arp->ar_hrd),
			(unsigned int)htons(arp->ar_pro),
			(unsigned int)arp->ar_hln,
			(unsigned int)arp->ar_pln,
			(unsigned int)htons(arp->ar_op)
			);
		printf("\n");
}

void print_ip_header(struct ip *ip) {
	char indnt[64] = "  ";
	struct protoent *ip_prot;

	printf("  IP HEADER:\n");
	ip_prot = getprotobynumber(ip->ip_p);
	if (ip_prot == NULL) {
		printf("Couldn't get IP Protocol\n");
		return;
		}
	printf("%sver=%d hlen=%u TOS=%u len=%u ID=0x%.2X", indnt,
#ifdef _IP_VHL
		ip->ip_vhl >> 4, (ip->ip_vhl & 0x0f) << 2,
#else
		ip->ip_v, ip->ip_hl<<2,
#endif
		(unsigned int)ip->ip_tos,
		(unsigned int)htons(ip->ip_len),
		(unsigned int)htons(ip->ip_id)
		);
	printf("\n%sFRAG=0x%.2x TTL=%u Proto=%s cksum=0x%.2X\n", indnt,
		htons(ip->ip_off),
		(unsigned int)ip->ip_ttl,
		ip_prot->p_name,
		htons(ip->ip_sum)
		);

	printf("%s%s", indnt, inet_ntoa(ip->ip_src) );
	printf(" -> %s\n", inet_ntoa(ip->ip_dst) );

}

#ifdef INET6
void print_ip6_header(struct ip6_hdr *ip) {
	char indnt[64] = "  ";
	struct protoent *ip_prot;

	printf("  IPv6 HEADER:\n");
	ip_prot = getprotobynumber(ip->ip6_nxt);
	if (ip_prot == NULL) {
		printf("Couldn't get IP Protocol\n");
		return;
		}
	printf("%sver=%u class=0x%.2X label=0x%.5X plen=%u nxt=%u hlim=%u\n", indnt,
		(unsigned int)(ip->ip6_vfc & 0xf0) >> 4,
		(unsigned int)(htonl(ip->ip6_flow) & 0x0ff00000) >> 20,
		(unsigned int)(htonl(ip->ip6_flow) & 0x000fffff),
		htons(ip->ip6_plen),
		(unsigned int)ip->ip6_nxt,
		(unsigned int)ip->ip6_hlim
		);

	printf("%s%s", indnt,
		inet_ntop(AF_INET6, &(ip->ip6_src), gstr, sizeof(gstr)) );
	printf(" -> %s\n",
		inet_ntop(AF_INET6, &(ip->ip6_src), gstr, sizeof(gstr)) );
}
#endif /* INET6 */

void print_tcp_header(struct tcphdr *tcp, unsigned int len, int wtp) {
	char indnt[64] = "    ";

	if (wtp & PP_SHOW_TCPHEADER) {
		printf("%sTCP HEADER:\n", indnt);
		printf("%ssport=%u dport=%u seq=0x%lX ack=0x%lX doff=0x%.2X\n",
			indnt,
			(unsigned int)htons(tcp->th_sport),
			(unsigned int)htons(tcp->th_dport),
			(unsigned long int)htonl(tcp->th_seq),
			(unsigned long int)htonl(tcp->th_ack),
			tcp->th_off
			);
		printf("%sflags=(0x%X)", indnt, (unsigned int)tcp->th_flags);
		if (tcp->th_flags & TH_FIN)	printf(",FIN");
		if (tcp->th_flags & TH_SYN)	printf(",SYN");
		if (tcp->th_flags & TH_RST)	printf(",RST");
		if (tcp->th_flags & TH_PUSH)	printf(",PUSH");
		if (tcp->th_flags & TH_ACK)	printf(",ACK");
		if (tcp->th_flags & TH_URG)	printf(",URG");
		printf(" win=%u cksm=0x%.4X urp=0x%.4X",
			htons(tcp->th_win),
			htons(tcp->th_sum),
			htons(tcp->th_urp)
			);
		printf("\n");
		}
	if (wtp & PP_SHOW_PACKETCONTENT) {
		u_char *p;
		unsigned int i;
		p = (u_char *)tcp;
		p += (tcp->th_off)*sizeof(int);
		len -= sizeof(struct tcphdr) + sizeof(int);
			/* Options (sizeof(int)) is there for padding */
		if (len>0) {
			for (i=0; i<len; i++)
				printf("%s", my_charconv(p[i]));
			printf("\n");
			}
		}
}

void print_udp_header(struct udphdr *udp, unsigned int len, int wtp) {

	if (wtp & PP_SHOW_UDPHEADER) {
		printf("\tUDP HEADER:\n");
		printf("\t\tsport=%u dport=%u len=%u cksum=0x%.2X\n",
			(unsigned int)htons(udp->uh_sport),
			(unsigned int)htons(udp->uh_dport),
			(unsigned int)htons(udp->uh_ulen),
			(unsigned int)htons(udp->uh_sum)
			);
		}
	if (wtp & PP_SHOW_PACKETCONTENT) {
		u_char *p;
		unsigned int i;
		p = (u_char *)udp;
		p += sizeof(struct udphdr);
		len -= sizeof(struct udphdr);
		for (i=0; i<len; i++)
			printf("%s", my_charconv(p[i]));
		printf("\n");
		}
}

void print_icmp_header(struct icmp *icmp, unsigned int len, int wtp) {

	if (wtp & PP_SHOW_ICMPHEADER) {
		printf("\tICMP HEADER:\n");
		printf("\t\ttype=0x%X code=0x%X cksum=0x%.4X\n",
			(unsigned int)icmp->icmp_type,
			(unsigned int)icmp->icmp_code,
			(unsigned int)htons(icmp->icmp_cksum)
			);
		}
	if (wtp & PP_SHOW_PACKETCONTENT) {
		u_char *p;
		unsigned int i;
		p = (u_char *)icmp;
		p += sizeof(struct icmp);
		len -= sizeof(struct icmp);
		for (i=0; i<len; i++)
			printf("%s", my_charconv(p[i]));
		printf("\n");
		}
}

#ifdef INET6
void print_icmp6_header(struct icmp6_hdr *icmp6, unsigned int len, int wtp) {

	if (wtp & PP_SHOW_ICMPHEADER) {
		printf("\tICMPv6 HEADER:\n");
		printf("\t\ttype=0x%X code=0x%X cksum=0x%.4X\n",
			(unsigned int)icmp6->icmp6_type,
			(unsigned int)icmp6->icmp6_code,
			(unsigned int)htons(icmp6->icmp6_cksum)
			);
		}
	if (wtp & PP_SHOW_PACKETCONTENT) {
		u_char *p;
		unsigned int i;
		p = (u_char *)icmp6;
		p += sizeof(struct icmp6_hdr);
		len -= sizeof(struct icmp6_hdr);
		for (i=0; i<len; i++)
			printf("%s", my_charconv(p[i]));
		printf("\n");
		}
}
#endif
