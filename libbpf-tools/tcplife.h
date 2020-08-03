/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __XFSSLOWER_H
#define __XFSSLOWER_H

#define DNAME_INLINE_LEN 32
#define TASK_COMM_LEN    16

#define MAX_CPUS 128
#define AF_INET		2	/* Internet IP Protocol 	*/
#define AF_INET6	10	/* IP version 6			*/



// data struct for both ipv4 and ipv6
struct ip_data {
    __u64 ts_us;
    __u8 direction;
    __u32 pid;
   	char comm[TASK_COMM_LEN];
    __u16 family;
    __u16 lport;
    __u16 dport;
    __u64 rx_b;
    __u64 tx_b;
    __u64 span_us;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
        
};

#endif /* __DRSNOOP_H */
