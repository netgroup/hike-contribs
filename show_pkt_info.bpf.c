// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* HIKe Prog Name comes always first */
#define HIKE_PROG_NAME    show_pkt_info

#define HIKE_DEBUG 1

#define REAL
//#define REPL

#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/seg6.h>
#include <linux/errno.h>

#ifdef REAL
  #include "tb_defs.h"
  #include "hike_vm.h"
  #include "parse_helpers.h"
  #include "ip6_hset.h"
  
#endif  

#ifdef REPL
  #define HIKE_DEBUG 1 
  #include "tb_defs.h"
  #include "ip6_hset_repl.h"
  #include "mock.h"

#endif

#define LAYER_2 1
#define NET_LAYER 2
#define TRANSP_LAYER 4


/* show_pkt_info ()
 * 
 * 
 * 
 * input:
 * - ARG1:	HIKe Program ID;
 * - ARG2:  which parts of the packet needs to be printed
 * - ARG3:  user supplied info
 *
 * 
*/
HIKE_PROG(HIKE_PROG_NAME) {


  struct pkt_info *info = hike_pcpu_shmem();
  struct hdr_cursor *cur;

  struct ethhdr *eth_h;

  int select_layers = HVM_ARG2;
  int user_info = HVM_ARG3;

  __u8 test;
  if (unlikely(!info))
    goto drop;

  /* take the reference to the cursor object which has been saved into
   * the HIKe per-cpu shared memory
   */
  cur = pkt_info_cur(info);
  /* no need for checking cur != NULL here */


  if (select_layers & LAYER_2) {

    if (!cur_may_pull(ctx, cur, sizeof(struct ethhdr )))
      goto drop;
      
    eth_h = (struct ethhdr *)cur_header_pointer(ctx, cur, cur->mhoff,
               sizeof(*eth_h));
    //DEBUG_PRINT("Layer 2 info : %c %c",eth_h->h_dest[0], eth_h->h_dest[1]);
    test= eth_h->h_dest[0];
    //DEBUG_PRINT("Layer 2 info : %u ",eth_h->h_dest[0]);
    //DEBUG_PRINT("Layer 2 info : %u",test);
    DEBUG_PRINT("Layer 2 info : ");
  }
  
  if (select_layers & NET_LAYER) {
    DEBUG_PRINT("Net Layer info : ");  
  }

  if (select_layers & TRANSP_LAYER) {
    DEBUG_PRINT("Transp Layer info : ");  
  }

  DEBUG_PRINT("User info : %u",user_info);


//out:

	return HIKE_XDP_VM;

drop:
  DEBUG_PRINT("drop packet");
	return HIKE_XDP_ABORTED;

  return 0;
}
EXPORT_HIKE_PROG(HIKE_PROG_NAME);

/* Export const */
EXPORT_HIKE_CONST(LAYER_2);
EXPORT_HIKE_CONST(NET_LAYER);
EXPORT_HIKE_CONST(TRANSP_LAYER);

#ifdef REAL
char LICENSE[] SEC("license") = "Dual BSD/GPL";
#endif
