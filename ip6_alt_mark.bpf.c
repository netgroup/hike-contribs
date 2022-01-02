// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#define HIKE_PROG_NAME	ipv6_alt_mark

#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <linux/seg6.h>
#include <linux/errno.h>

#include <linux/udp.h>

/* HIKe Chain IDs and XDP eBPF/HIKe programs IDs */
#include "minimal.h"

#include "parse_helpers.h"
#include "hike_vm.h"

/* HIKe eBPF Program
 *
 * Check if header contains hbh header with alt mark
 *
 * Beware that the hdr_cursor may be updated also in case that an error occurs
 * during the packet processing.
 *
 * input:
 *  - ARG1:	HIKe Progam ID.
 *
 *  output:
 *   - HVM_RET:	ret code (rc) operation
 *
 *  The returned code (rc for short) can
 *  be either:
 *
 *  In case of error, the program *does* not return the control to the HIKe
 *  VM and it aborts the packet processing operation (i.e.: drops the packet).
 *  Otherwise, the flow control is returned back to the HIKe VM which
 *  continues to execute the processing in the calling chain.
 */
HIKE_PROG(HIKE_PROG_NAME)
{
	struct pkt_info *info = hike_pcpu_shmem();
	struct hdr_cursor *cur;
	struct ipv6hdr *ip6h;
	struct ipv6_hopopt_hdr *hopopt_h;
	bool found = false;
	bool final = false;
	__u8 nexthdr;
	int start;
	int len;
	int rc;

	if (unlikely(!info))
		goto error;

	/* take the reference to the cursor object which has been saved into
	 * the HIKe per-cpu shared memory
	 */
	cur = pkt_info_cur(info);
	/* no need for checking cur != NULL here */

	ip6h = (struct ipv6hdr *)cur_header_pointer(ctx, cur, cur->nhoff,
						    sizeof(*ip6h));
	if (unlikely(!ip6h))
		goto error;

	nexthdr = ip6h->nexthdr;

	rc = 0;
	if (nexthdr == IPPROTO_HOPOPTS) {
		if (!cur_may_pull(ctx, cur, sizeof(struct ipv6_hopopt_hdr )))
			goto error;

		hopopt_h = (struct ipv6_hopopt_hdr *)cur_header_pointer(ctx, cur, cur->dataoff,
							    sizeof(*hopopt_h));
		if (unlikely(!hopopt_h))
			goto error;

		__pull(cur, sizeof(*hopopt_h));

		rc = 1;
		goto out;
	}


out:
	/* return code for the invoking HIKe Chain */
	HVM_RET = rc;
	/* return code for the HIKe VM */
	return HIKE_XDP_VM;

error:
	return XDP_ABORTED;
}
EXPORT_HIKE_PROG(HIKE_PROG_NAME);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
