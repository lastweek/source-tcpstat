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
 * $Id: tcpprof.h,v 1.9 2002/01/19 04:31:36 pherman Exp $
 */

#ifndef TCPPROF_TCPPROF_H
#define TCPPROF_TCPPROF_H

#include "tcpstat.h"

	/* Types of statistics to measure */
#define TYPE_ALL		0x01
#define TYPE_LINK		0x02
#define TYPE_IP_PROTO		0x04
#define TYPE_PORT		0x08
#define TYPE_HOST		0x10
#define TYPE_NET		0x20


typedef struct stat_root {
	u_int		type;
	u_int		count;
	struct stat_unit **hash;
} stat_root;

/* stats.c protos */
int stats_initdb(u_int types);
int stats_closedb();
void stats_insert(packet_data *pd, u_int types);
void show_results(u_int types);

#endif /* TCPPROF_TCPPROF_H */

/**************** END *****************/
