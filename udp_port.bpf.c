// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#define HIKE_PROG_NAME	udp_port

#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/seg6.h>

#define REAL
/* HIKe Chain IDs and XDP eBPF/HIKe programs IDs */
//#include "minimal.h"

#include "ip6_hset.h"
#include "parse_helpers.h"
#include "hike_vm.h"

#define NEXT_HEADER_UDP 17

HIKE_PROG(HIKE_PROG_NAME)
{
	struct pkt_info *info = hike_pcpu_shmem();
	struct ipv6_hset_nh nh;
	struct udp_dst_port dp;
	// const __u32 port = __to_u32(HVM_ARG2);
	struct hdr_cursor *cur;
	int rc;

	cur = pkt_info_cur(info);
	if (unlikely(!cur))
		goto drop;

	rc = ipv6_get_nh(ctx, cur, &nh);
	if (rc < 0)
		goto drop;

	DEBUG_HKPRG_PRINT("Prova DEBUG_HKPRG_PRINT, nh: %d", nh.next_header);

	if (nh.next_header != NEXT_HEADER_UDP)
		goto drop;

	ipv6_get_udp_port(ctx, cur, &dp);
	DEBUG_HKPRG_PRINT("Prova DEBUG_HKPRG_PRINT, port: %u", dp.dst_port);

	return HIKE_XDP_VM;

drop:
	DEBUG_HKPRG_PRINT(" : drop packet");
	return HIKE_XDP_ABORTED;
}
EXPORT_HIKE_PROG(HIKE_PROG_NAME);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
