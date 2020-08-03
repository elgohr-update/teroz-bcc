/* SPDX-License-Identifier: GPL-2.0 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "tcplife.h"

//----------------------------------- trace tcp flows --------------------------------------------------------------------

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u64);
	__type(value, struct sock *);
} birth SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");


struct id_t {
    __u32 pid;
    __u8 direction;
    char task[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct sock  *);
	__type(value, struct id_t);
} whoami SEC(".maps");



 SEC("tracepoint/sock/inet_sock_set_state")
 int inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
 {
    if (ctx->protocol != IPPROTO_TCP)
        return 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 direction = 0;
    // sk is mostly used as a UUID, and for two tcp stats:
    
    struct sock *sk = (struct sock *)ctx->skaddr;

    if (!sk)		
        return 0;
    
    /*
     * This tool includes PID and comm context. It's best effort, and may
     * be wrong in some situations. It currently works like this:
     * - record timestamp on any state < TCP_FIN_WAIT1
     * - cache task context on:
     *       TCP_SYN_SENT: tracing from client
     *       TCP_LAST_ACK: client-closed from server
     * - do output on TCP_CLOSE:
     *       fetch task context if cached, or use current task
     */
    // capture birth time
    if (ctx->newstate < TCP_FIN_WAIT1) {
        /*
         * Matching just ESTABLISHED may be sufficient, provided no code-path
         * sets ESTABLISHED without a tcp_set_state() call. Until we know
         * that for sure, match all early states to increase chances a
         * timestamp is set.
         * Note that this needs to be set before the PID filter later on,
         * since the PID isn't reliable for these early stages, so we must
         * save all timestamps and do the PID filter later when we can.
         */
        __u64 ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&birth,&sk,&ts,0);
    }
    // record PID & direction  https://blog.confirm.ch/tcp-connection-states/
    if (ctx->newstate == TCP_SYN_SENT || ctx->newstate == TCP_LAST_ACK) {
        struct id_t me = {.pid = pid,.direction = ctx->newstate == TCP_LAST_ACK && ctx->oldstate == TCP_CLOSE_WAIT ? 1:0};
        bpf_map_update_elem(&whoami,&sk,&me,0);
    }
    if (ctx->newstate != TCP_CLOSE)
        return 0;
    
    // calculate lifespan
    __u64 *tsp, delta_us;
    tsp = bpf_map_lookup_elem(&birth,&sk);
    if (tsp == 0) {
        bpf_map_delete_elem(&whoami,&sk); // may not exist
        return 0;                         // missed create
    }
    delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
    bpf_map_delete_elem(&birth,&sk);
    
    // fetch possible cached data, and filter
    struct id_t *mep;
    mep = bpf_map_lookup_elem(&whoami,&sk);
    if (mep != 0){
        pid = mep->pid;
        direction = mep->direction;
    }
    
    
    struct tcp_sock *tp =  (struct tcp_sock *)sk;
    
    // get throughput stats. see tcp_get_info().
    __u64 rx_b =0,tx_b =0;

    bpf_core_read(&rx_b,sizeof(rx_b),&tp->bytes_received);
    bpf_core_read(&tx_b,sizeof(tx_b),&tp->bytes_acked);

    

    __u16 lport = ctx->sport;
    __u16 dport = ctx->dport;
    __u64 key = dport + ((0ULL + lport) << 32);
   
    
    if (ctx->family == AF_INET) {
        struct ip_data data4 = {};
        data4.span_us = delta_us;
        data4.family = AF_INET;
        data4.rx_b = rx_b;
        data4.tx_b = tx_b;
        data4.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_probe_read_str(&data4.saddr,sizeof(data4.saddr),ctx->saddr);
        bpf_probe_read_str(&data4.daddr,sizeof(data4.daddr),ctx->daddr);
        data4.lport = lport;
        data4.dport = dport;
        data4.pid = pid;
        data4.direction = direction;
        bpf_get_current_comm(&data4.comm, sizeof(data4.comm));
	

        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,&data4,sizeof(data4));

    } else /* 6 */ {
        struct ip_data data6 = {};
        data6.span_us = delta_us;
        data6.family = AF_INET6;
        data6.rx_b = rx_b;
        data6.tx_b = tx_b;
        data6.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_probe_read_str(&data6.saddr_v6,sizeof(data6.saddr_v6),ctx->saddr_v6);
        bpf_probe_read_str(&data6.daddr_v6, sizeof(data6.daddr_v6),ctx->daddr_v6);
        data6.lport = lport;
        data6.dport = dport;
        data6.pid = pid;
        data6.direction = direction;
        bpf_get_current_comm(&data6.comm, sizeof(data6.comm));
	
        
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,&data6,sizeof(data6));
   }
    if (mep != 0)
        bpf_map_delete_elem(&whoami,&sk);

    return 0;
}

char _license[] SEC("license") = "GPL";
