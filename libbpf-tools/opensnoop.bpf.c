// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
// Copyright (c) 2020 Netflix
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "opensnoop.h"

#define TASK_RUNNING 0

const volatile __u64 min_us = 0;
const volatile pid_t targ_pid = 0;
const volatile pid_t targ_tgid = 0;
const volatile uid_t targ_uid = 0;
const volatile bool targ_failed = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct args_t);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline bool valid_uid(uid_t uid) {
	return uid != INVALID_UID;
}

static __always_inline
int trace_filtered(u32 tgid, u32 pid)
{
	u32 uid;

	/* filters */
	if (targ_tgid && targ_tgid != tgid)
		return 1;
	if (targ_pid && targ_pid != pid)
		return 1;
	if (valid_uid(targ_uid)) {
		uid = (u32)bpf_get_current_uid_gid();
		if (targ_uid != uid) {
			return 1;
		}
	}
	return 0;
}

// SEC("tracepoint/syscalls/sys_enter_open")
// int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter* ctx)
// {
// 	u64 id = bpf_get_current_pid_tgid();
// 	/* use kernel terminology here for tgid/pid: */
// 	u32 tgid = id >> 32;
// 	u32 pid = id;

// 	/* store arg info for later lookup */
// 	if (!trace_filtered(tgid, pid)) {
// 		struct args_t args = {};
// 		args.fname = (const char *)ctx->args[0];
// 		args.flags = (int)ctx->args[1];
// 		bpf_map_update_elem(&start, &pid, &args, 0);
// 	}
// 	return 0;
// }

// SEC("tracepoint/syscalls/sys_enter_openat")
// int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx)
// {
// 	u64 id = bpf_get_current_pid_tgid();
// 	/* use kernel terminology here for tgid/pid: */
// 	u32 tgid = id >> 32;
// 	u32 pid = id;

// 	/* store arg info for later lookup */
// 	if (!trace_filtered(tgid, pid)) {
// 		struct args_t args = {};
// 		args.fname = (const char *)ctx->args[1];
// 		args.flags = (int)ctx->args[2];
// 		bpf_map_update_elem(&start, &pid, &args, 0);
// 	}
// 	return 0;
// }

// static __always_inline
// int trace_exit(struct trace_event_raw_sys_exit* ctx)
// {
// 	struct event event = {};
// 	struct args_t *ap;
// 	int ret;
// 	u32 pid = bpf_get_current_pid_tgid();

// 	ap = bpf_map_lookup_elem(&start, &pid);
// 	if (!ap)
// 		return 0;	/* missed entry */
// 	ret = ctx->ret;
// 	if (targ_failed && ret >= 0)
// 		goto cleanup;	/* want failed only */

// 	/* event data */
// 	event.pid = bpf_get_current_pid_tgid() >> 32;
// 	event.uid = bpf_get_current_uid_gid();
// 	bpf_get_current_comm(&event.comm, sizeof(event.comm));
// 	bpf_probe_read_str(&event.fname, sizeof(event.fname), ap->fname);
// 	event.flags = ap->flags;
// 	event.ret = ret;

// 	/* emit event */
// 	// bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
// 	// 		      &event, sizeof(event));

// cleanup:
// 	bpf_map_delete_elem(&start, &pid);
// 	return 0;
// }

// SEC("tracepoint/syscalls/sys_exit_open")
// int tracepoint__syscalls__sys_exit_open(struct trace_event_raw_sys_exit* ctx)
// {
// 	return trace_exit(ctx);
// }

// SEC("tracepoint/syscalls/sys_exit_openat")
// int tracepoint__syscalls__sys_exit_openat(struct trace_event_raw_sys_exit* ctx)
// {
// 	return trace_exit(ctx);
// }


// }
 SEC("tracepoint/sock/inet_sock_set_state")
 int inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
 {
    if (ctx->protocol != IPPROTO_TCP)
        return 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 direction = 0;
    // sk is mostly used as a UUID, and for two tcp stats:
    
    struct sock *sk = (struct sock *)ctx->skaddr;

    // if (!sk)		
    //     return 0;
    
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
    // if (ctx->newstate < TCP_FIN_WAIT1) {
    //     /*
    //      * Matching just ESTABLISHED may be sufficient, provided no code-path
    //      * sets ESTABLISHED without a tcp_set_state() call. Until we know
    //      * that for sure, match all early states to increase chances a
    //      * timestamp is set.
    //      * Note that this needs to be set before the PID filter later on,
    //      * since the PID isn't reliable for these early stages, so we must
    //      * save all timestamps and do the PID filter later when we can.
    //      */
    //     __u64 ts = bpf_ktime_get_ns();
    //     bpf_map_update_elem(&birth,&sk,&ts,0);
    // }
    // record PID & direction  https://blog.confirm.ch/tcp-connection-states/
    // if (ctx->newstate == TCP_SYN_SENT || ctx->newstate == TCP_LAST_ACK) {
    //     struct id_t me = {.pid = pid,.direction = ctx->newstate == TCP_LAST_ACK && ctx->oldstate == TCP_CLOSE_WAIT ? 1:0};
    //     bpf_map_update_elem(&whoami,&sk,&me,0);
    // }
    if (ctx->newstate != TCP_CLOSE)
        return 0;
    
	struct tcp_sock *tp =  (struct tcp_sock *)sk;
    
    // get throughput stats. see tcp_get_info().
    __u64 rx_b =0,tx_b =0;

    bpf_core_read(&rx_b,sizeof(rx_b),&tp->bytes_received);
    bpf_core_read(&tx_b,sizeof(tx_b),&tp->bytes_acked);
	
	struct event event = {};
	
	/* event data */
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.uid = bpf_get_current_uid_gid();
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	//bpf_probe_read_str(&event.fname, sizeof(event.fname), ap->fname);
	event.rx_b = rx_b;
	event.tx_b = tx_b;

	/* emit event */
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));




    
    return 0;
}


char LICENSE[] SEC("license") = "GPL";
