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
 * $Id: stats.c,v 1.22 2002/01/19 04:31:36 pherman Exp $
 */

#include "tcpprof.h"
#include <fcntl.h>

#ifdef USE_DB1_LIBRARY
#  include <db1/db.h>
#else
#  include <db.h>
#endif

extern char numbers_only;
extern char registered_only;
extern char src_dest_split;
extern int ports_to_show;
extern int lines_to_show;

int		tc;

/* This is the key used in our B-Tree and includes
 * data that would differentiate the data from the
 * rest of the data
 */
typedef struct stkey {
	u_int	key;
	char	direction;
} stkey_t;

typedef struct stat_unit {
	u_quad_t bytes;
	u_quad_t num_packets;
} stat_unit;

typedef struct stat_info {
	stkey_t	key;
	stat_unit unit;
} stat_info;

typedef struct data_base {
	u_int	type;
	DB	*db;
} data_base;

data_base	*dbs;

#define FIRST_COLUMN_WIDTH	25		/* how wide the first column should be */
const char *type_str[] = { "Total", "Link", "IP", "Port", "Host", "Network" };

int compare_keys(const DBT *d1, const DBT *d2) {
	stkey_t *k1, *k2;
	if (d1 == NULL || d2 == NULL) return 0;
	k1 = (stkey_t *)d1->data;
	k2 = (stkey_t *)d2->data;

	if (src_dest_split) {
		if (k1->key == k2->key) {
			if (k1->direction == k2->direction) return 0;
			return (k1->direction < k2->direction)? -1 : 1;
			}
		return (k1->key < k2->key)? -1 : 1;
		}
	else  {
		if (k1->key == k2->key) return 0;
		return (k1->key < k2->key)? -1 : 1;
		}
	return 0;
}

/* returns:
 *	-1	- error
 *	 0	- found
 *	 1	- not found
 */
int find_entry(data_base *dbp, stkey_t *key, stat_unit *su) {
	DB *db = dbp->db;
	DBT dbt, key_dbt;
	int ret;

	key_dbt.data = (void *) key;
	key_dbt.size = sizeof(stkey_t);
	ret = db->get(db, &key_dbt, &dbt, 0);
	if (dbt.data != NULL && ret == 0)
		bcopy(dbt.data, (void *) su, sizeof(stat_unit) );
	return ret;
}

int next_entry(data_base *dbp, stkey_t *key, stat_unit *su) {
	DB *db = dbp->db;
	DBT dbt, key_dbt;
	int ret;

	key_dbt.data = (void *) key;
	key_dbt.size = sizeof(stkey_t);
	ret = db->seq(db, &key_dbt, &dbt, (key->key == 0)? R_FIRST : R_NEXT);
	if (dbt.data != NULL && ret == 0) {
		bcopy(dbt.data, (void *) su, sizeof(stat_unit) );
		bcopy(key_dbt.data, (void *) key, sizeof(stkey_t) );
		}
	return ret;
}

int add_entry(data_base *dbp, stkey_t *key, stat_unit *su) {
	DB *db = dbp->db;
	DBT dbt, key_dbt;
	int ret;

	key_dbt.data = (void *) key;
	key_dbt.size = sizeof(stkey_t);
	dbt.data = (void *) su;
	dbt.size = sizeof(stat_unit);
	ret = db->put(db, &key_dbt, &dbt, 0);
	return ret;
}

int stats_initdb(u_int s_types) {
	int i, j;
	BTREEINFO bi;

	tc = count_1bits(s_types);
	if (tc == 0) return 1;
	dbs = (data_base *) malloc(tc*sizeof(data_base));
	if (dbs == NULL) return -1;

	bi.flags = 0;
	bi.cachesize = 0;
	bi.maxkeypage = 0;
	bi.minkeypage = 0;
	bi.psize = 0;
	bi.compare = &compare_keys;
	bi.prefix = NULL;
	bi.lorder = 0;

		/* Init stat_r */
	for (i=0,j=0; i<tc && j<32; j++) {
		if ( (s_types>>j) & 0x1) {
			dbs[i].type = 1<<j;
			dbs[i].db = dbopen(NULL, O_RDWR, 0600, DB_BTREE, &bi);
			if (dbs[i].db == NULL) {
				perror("dbopen");
				return -1;
				}
			i++;
			}
		}
	return 0;
}

int stats_closedb() {
	int i;
	DB *db;
	for (i=0; i<tc; i++) {
		db = dbs[i].db;
		db->sync(db, 0);
		db->close(db);
		}
	return 0;
}

int bytes_compare(const void *h1, const void *h2) {
	const stat_info *a, *b;

	a = (const stat_info *)h1;
	b = (const stat_info *)h2;

		/* It's reversed here ... */
	return (a->unit.bytes < b->unit.bytes)? 1 : 
		(a->unit.bytes > b->unit.bytes)? -1 : 0;
}

void print_line(char *label, char *suffix, u_quad_t num_p, u_quad_t bytes, Double pcnt) {
	char str[1024];
	sprintf(str, "%s %s", label, suffix);		/* XXX: Why is this here? */
	printf("\t%-*s%-10qu%-10qu%-5.4f %%\n", FIRST_COLUMN_WIDTH, str, num_p, bytes, pcnt);
}

int get_data_from_packet(stkey_t *key, u_int t, packet_data *p, char source) {
	u_int	r, is_ippacket = 0, is_ip6packet = 0;
	u_short et;
	struct ether_header *eh;
	struct ip_packet *ipp;
	struct tcphdr *th;
	struct udphdr *uh;

	eh =  &(p->ether);
	ipp = &(p->data.ip);
	th = &(ipp->body.tcphdr);
	uh = &(ipp->body.udphdr);

		/* Keep track of loop back data */
	et = ntohs(eh->ether_type);

	is_ippacket =  is_ip_packet(p);
#ifdef INET6
	is_ip6packet =  is_ip6_packet(p);
#endif
	key->key = 0;
	switch (t) {
		case TYPE_ALL:
			key->key = 2;
			break;
		case TYPE_LINK:
			key->key = p->link_type + 1;
			break;
		case TYPE_IP_PROTO:
			if (is_ippacket)
				key->key = ipp->hdr.ip_p + 1;
#ifdef INET6
			else if (is_ip6packet)
				key->key = get_ip_proto(p) + 1;
#endif
			break;
		case TYPE_PORT:
			if (!is_ippacket) break;
			if (ipp->hdr.ip_p == IPPROTO_TCP)
				r = (source)?
					htons(th->th_sport) :
					htons(th->th_dport);
			else if (ipp->hdr.ip_p == IPPROTO_UDP)
				r = (source)?
					htons(uh->uh_sport) :
				 	htons(uh->uh_dport);
			else r = 0;
			if (r >= (u_int)ports_to_show && registered_only) r = 0;
			key->key = r;
			break;
		case TYPE_HOST:	/* XXX: Assume 32 bit IP Addresses */
			if (!is_ippacket) break;
			key->key = (source)?
				*(u_int*)&(ipp->hdr.ip_src) :
				*(u_int*)&(ipp->hdr.ip_dst);
			break;
		case TYPE_NET:
			if (!is_ippacket) break;
			key->key = (source)?
				inet_netof(ipp->hdr.ip_src) :
				inet_netof(ipp->hdr.ip_dst);
			break;
		default: break;
		}
	return 0;
}

void add_packet(data_base *dbp, stkey_t *key, packet_data *pd) {
	stat_unit su;
	int er;

	er = find_entry(dbp, key, &su);
	if (er == -1) {
		perror("Fatal! find_entry()");
		exit(0);
		}
	if (er == 0) {		/* Key found in the file */
		su.num_packets++;
		su.bytes += pd->packet_len;
		er = add_entry(dbp, key, &su);
		if (er == -1) {
			perror("Fatal! add_entry()");
			exit(0);
			}
		}
	else {			/* Key not found, insert into db */
		su.bytes = pd->packet_len;
		su.num_packets = 1;
		er = add_entry(dbp, key, &su);
		if (er == -1) {
			perror("Fatal! add_entry()");
			exit(0);
			}
		}
}

void show_totals(u_int type, u_int count, stat_info *sip, u_quad_t tb) {
	char str[256];
	u_int	i, key;
	Double pcnt;
	u_quad_t l, b;
	stat_unit *u;
	struct in_addr	*addr;

	b = 0;
	u = NULL;
	switch (type) {
		case TYPE_ALL:
		for (l=0; l<count; l++) {
			u = &sip[l].unit;
			b += u->bytes;
			}
		pcnt = 100.0 * (Double)b/(Double)tb;
		print_line( "Total", "", u->num_packets, b, pcnt);
		break;
		case TYPE_LINK:
		for (l=0; l<count; l++) {
			u = &sip[l].unit;
			key = sip[l].key.key - 1;
			b = u->bytes;
			if (key & LINK_ETHERNET) {
				switch (key & LINK_ETHERNET_OTHER) {
				    case LINK_ETHERNET_IP:
					sprintf(str, "Ethernet (IP):"); break;
#ifdef INET6
				    case LINK_ETHERNET_IP6:
					sprintf(str, "Ethernet (IPv6):"); break;
#endif
				    case LINK_ETHERNET_ARP:
					sprintf(str, "Ethernet (arp):"); break;
				    case LINK_ETHERNET_REVARP:
					sprintf(str, "Ethernet (revarp):"); break;
				    case LINK_ETHERNET_IPX:
					sprintf(str, "Ethernet (IPX):"); break;
				    case LINK_ETHERNET_AT:
					sprintf(str, "Ethernet (AppleTalk):"); break;
				    case LINK_ETHERNET_AARP:
					sprintf(str, "Ethernet (AppleTalk ARP):"); break;
				    default:
					sprintf(str, "Ethernet (other):"); break;
				    }
				}
			else if (key & LINK_PPP) {
				switch (key & LINK_PPP_OTHER) {
				    case LINK_PPP_IP:
					sprintf(str, "PPP (IP):"); break;
#ifdef INET6
				    case LINK_PPP_IP6:
					sprintf(str, "PPP (IPv6):"); break;
				    case LINK_PPP_IPCP6:
					sprintf(str, "PPP (IPCP6):"); break;
#endif
				    case LINK_PPP_IPCP:
					sprintf(str, "PPP (IPCP):"); break;
				    case LINK_PPP_LCP:
					sprintf(str, "PPP (LCP):"); break;
				    case LINK_PPP_CCP:
					sprintf(str, "PPP (CCP):"); break;
				    case LINK_PPP_PAP:
					sprintf(str, "PPP (PAP):"); break;
				    case LINK_PPP_CHAP:
					sprintf(str, "PPP (CHAP):"); break;
				    default:
					sprintf(str, "PPP (other):"); break;
				    }
			   }
			else if (key & LINK_NONE) {
				switch (key & LINK_NONE_OTHER) {
				    case LINK_NONE_IP:
					sprintf(str, "No Link (IP):"); break;
#ifdef INET6
				    case LINK_NONE_IP6:
					sprintf(str, "No Link (IPv6):"); break;
#endif
				    default:
					sprintf(str, "No Link (non-IP):"); break;
				    }
			   }
			else {
				if (key & 0x0100)
					sprintf(str, "UNKNOWN (IP):");
				else
					sprintf(str, "UNKNWON (non-IP):");
			}
			pcnt = 100.0 * (Double)b/(Double)tb;
			print_line(str, "", u->num_packets, b, pcnt);
			}
		break;
		case TYPE_IP_PROTO:
		for (l=0; l<count; l++) {
			u = &sip[l].unit;
			key = sip[l].key.key;
			b = u->bytes;
			pcnt = 100.0 * (Double)b/(Double)tb;
			print_line(
				my_get_proto(key - 1, numbers_only), "",
				u->num_packets, b, pcnt);
			}
			break;
		case TYPE_PORT:
		for (l=0; l<count; l++) {
			u = &sip[l].unit;
			key = sip[l].key.key;
			b = u->bytes; pcnt = 100.0 * (Double)b/(Double)tb;
			print_line(
				my_get_port((u_short)key, numbers_only),
				(src_dest_split)? ((sip[l].key.direction)? "< " : "> ") : "",
				u->num_packets, b, pcnt);
			}
			break;
		case TYPE_HOST:
		case TYPE_NET:
		for (l=0; l<count; l++) {
			u = &sip[l].unit;
			key = sip[l].key.key;
			b = u->bytes; pcnt = 100.0 * (Double)b/(Double)tb;
			i = key;
			addr = (struct in_addr *)&i;
			if (numbers_only || type == TYPE_NET)
				sprintf(str, "%s", inet_ntoa(*addr));
			else {
				struct hostent *he;
				he = gethostbyaddr((char *)addr, 4, AF_INET);
				str[0] = 0;
				if (he != NULL && he->h_name != NULL)
					strncat(str, he->h_name, FIRST_COLUMN_WIDTH - 1
					- ((src_dest_split)? 2 : 0));

				else
					sprintf(str, "%s", inet_ntoa(*addr));
				}
			print_line(str, 
				(src_dest_split)? ((sip[l].key.direction)? "< " : "> ") : "",
				u->num_packets, b, pcnt);
			}
			break;
		default:
		for (l=0; l<count; l++) {
			u = &sip[l].unit;
			key = sip[l].key.key;
			b = u->bytes; pcnt = 100.0 * (Double)b/(Double)tb;
			printf("\t%-20X%-10qu%-10qu%-5.4f %%\n",
				key, u->num_packets, b, pcnt);
			}
			break;
		}
}

void stats_insert(packet_data *pd, u_int types) {
	u_int i, type;
	stkey_t key1, key2;

	for (i=0; i<(u_int)tc; i++) {
		type=dbs[i].type;
		key1.direction = 0;
		key2.direction = 0;
		switch (type) {
			case TYPE_PORT:
			case TYPE_HOST:
			case TYPE_NET:
				/* Add src */
			get_data_from_packet(&key1, type, pd, 1);
			if (key1.key)
				add_packet(&dbs[i], &key1, pd);
				/* Add dest */
			if (src_dest_split) key2.direction = 1;
			get_data_from_packet(&key2, type, pd, 0);
			if (key2.key && (key2.key != key1.key || src_dest_split))
				/* Don't count duplicates if we don't differeciate src/dest */
				add_packet(&dbs[i], &key2, pd);
				break;
			default:
			get_data_from_packet(&key1, type, pd, 1);
			if (key1.key)
				add_packet(&dbs[i], &key1, pd);
				break;
			}
		}
}

u_int extract_entries(data_base *dbp, stat_info **sia) {
	u_int count = 0;
	int er;
	void *ptr;
	stat_unit su;
	stkey_t key;

	key.key = 0;
	if (*sia != NULL) { free(*sia); *sia = NULL; }
	for (;;) {
		er = next_entry(dbp, &key, &su);
		if (er != 0) break;
		count++;
		ptr = (void *) realloc(*sia, count*sizeof(stat_info));
		if (ptr == NULL) break;
		else *sia = (stat_info *) ptr;
		bcopy((void *)&su, (void *)&(*sia)[count-1].unit, sizeof(stat_unit));
		bcopy(&key, &(*sia)[count-1].key, sizeof(stkey_t));
		}
	return count;
}

void show_results(u_int types) {
	stat_info *sunits;
	int i, count;
	u_quad_t tot;


	sunits = NULL;

	count = extract_entries(&dbs[0], &sunits);
	if (count < 1) {
		fprintf(stderr, "No packets processed.\n");
		return;
		}
	tot = sunits[0].unit.bytes;
	printf("%s Statistics:\n", type_str[ffs(dbs[0].type)-1] );
	show_totals(dbs[0].type, 1, sunits, tot);

	for (i=1; i<tc; i++) {
		printf("%s Statistics:\n", type_str[ffs(dbs[i].type)-1] );
		count = extract_entries(&dbs[i], &sunits);
		qsort(sunits, count, sizeof(stat_info), bytes_compare);
		if (lines_to_show > -1)
			count = (lines_to_show<count)? lines_to_show : count;
		show_totals(dbs[i].type, count, sunits, tot);
		}
	if (sunits != NULL) free(sunits);
}
