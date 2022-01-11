// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#define HIKE_PROG_NAME	time
#define HIKE_DEBUG 1

/* HIKe Chain IDs and XDP eBPF/HIKe programs IDs */

#include "hike_vm.h"

bpf_map(map_time, ARRAY, __u32, __u64, 1);

HIKE_PROG(HIKE_PROG_NAME)
{
	__u64 boot_time;

	boot_time = bpf_ktime_get_boot_ns();
	if (unlikely(!boot_time))
		goto drop;
    DEBUG_HKPRG_PRINT("boot time: %llu\n", boot_time);
	return HIKE_XDP_VM;
    
drop:
	DEBUG_HKPRG_PRINT("drop packet");
	return HIKE_XDP_ABORTED;
}
EXPORT_HIKE_PROG(HIKE_PROG_NAME);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
