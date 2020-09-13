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
 * $Id: tcpseq.c,v 1.3 2002/01/02 21:05:55 pherman Exp $
 */

#include "tcpstat.h"

struct tcpseq_ha {
	struct in_addr	src;
	struct in_addr	dst;
	u_int port;
};

struct tcpseq_hash {
	struct tcpseq_hash	*next;
	struct tcpseq_ha	addr;
	u_int			seq;
	u_int			ack;
};

struct tcpseq_stats {
	u_int		opened_connections;	/* doesn't include full */
	u_int		closed_connections;	/* doesn't include full */
	u_int		full_connections;	/* opened AND closed */
};

struct tcpseq_hash	hash_first;

int tcpseq_addtostats(packet_data *pd) {
	u_char	flags;
	struct tcpseq_ha test_ha;
	struct tcphdr *tp = NULL;
	struct ip *ip;
#ifdef INET6
	int is_ip6 = 0;
	struct ip6_hdr *ip6;

	ip6 = (struct ip6_hdr *) &pd->data.ip6.hdr;
	if (is_ip6_packet(pd))
		tp= &(pd->data.ip6.body.tcphdr);
#endif

	ip = (struct ip *) &pd->data.ip.hdr;
        if (is_ip_packet(pd))
		tp= &(pd->data.ip.body.tcphdr);

	if (tp == NULL) return -1;

	flags = tp->th_flags;
	if (flags & TH_ACK) {
		bzero(&test_ha, sizeof(test_ha));

		}
	return 0;
}
