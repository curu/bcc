#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# dslower    trace process block in D state
#               For Linux, uses BCC, eBPF.
#
# This script traces high delay between process sleep in D state and been woken
#
# USAGE: dslower [-p PID] [-t TID] [-P] [min_us]
#
# REQUIRES: Linux 4.9+ (BPF_PROG_TYPE_PERF_EVENT support).
#
# This measures the time between a task was switched off cpu because of uninterruptible sleep and 
# been woken up.
# ie. sched_switch -> ttwu_do_wakeup
# Copyright 2022 Tencent
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 28-Nov-2022   Curu Wong

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime

# arguments
examples = """examples:
    ./dslower         # trace run queue latency higher than 10000 us (default)
    ./dslower 1000    # trace run queue latency higher than 1000 us
    ./dslower -p 123  # trace pid 123
    ./dslower -t 123  # trace tid 123 (use for threads only)
    ./dslower -P      # also show previous task comm and TID
"""
parser = argparse.ArgumentParser(
    description="Trace high run queue latency",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("min_us", nargs="?", default='10000',
    help="minimum sleep time to trace, in us (default 10000)")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)

thread_group = parser.add_mutually_exclusive_group()
thread_group.add_argument("-p", "--pid", metavar="PID", dest="pid",
    help="trace this PID only", type=int)
thread_group.add_argument("-t", "--tid", metavar="TID", dest="tid",
    help="trace this TID only", type=int)
args = parser.parse_args()

min_us = int(args.min_us)
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>

#ifndef TASK_NOLOAD
#define TASK_NOLOAD         0x0400
#endif

BPF_ARRAY(start, u64, MAX_PID);

struct rq;

struct data_t {
    u32 pid;
    char task[TASK_COMM_LEN];
    u64 delta_us;
};

BPF_PERF_OUTPUT(events);


// calc wakup delay
static int trace_wakeup(CTX_TYPE *ctx, struct task_struct *p)
{
    u64 *tsp, delta_us;
    u32 pid = p->pid;
    u32 tgid = p->tgid;

    if (FILTER_PID || FILTER_TGID || pid == 0)
        return 0;

    u64 ts = bpf_ktime_get_ns();

    // fetch timestamp and calculate delta
    tsp = start.lookup(&pid);
    if ((tsp == 0) || (*tsp == 0)) {
        return 0;   // missed enqueue
    }

    if(ts < *tsp){
        //maybe time wrap
        *tsp = 0;
        return 0;
    }

    delta_us = (ts - *tsp) / 1000;
    *tsp = 0;

    if (FILTER_US){
        return 0;
    }

    struct data_t data = {};
    data.pid = pid;
    data.delta_us = delta_us;
    bpf_probe_read(&data.task, sizeof(data.task), p->comm);

    // output
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}


static int trace_offcpu(struct task_struct *prev)
{
    u32 pid, tgid;

    // prev task go to sleep
    if ((prev->STATE_FIELD & TASK_UNINTERRUPTIBLE) && !(prev->STATE_FIELD & TASK_NOLOAD)) {
        pid = prev->pid;
        tgid = prev->tgid;
        u64 ts = bpf_ktime_get_ns();
        if (pid != 0) {
            if (!(FILTER_PID) && !(FILTER_TGID)) {
                start.update(&pid, &ts);
            }
        }
    }

    return 0;
}
"""

bpf_text_kprobe = """
int trace_ttwu_do_wakeup(struct pt_regs *ctx, struct rq *rq, struct task_struct *p,
    int wake_flags)
{
    return trace_wakeup(ctx, p);
}

int trace_run(struct pt_regs *ctx, struct rq *rq, struct task_struct *prev)
{
    return trace_offcpu(prev);
}
"""

bpf_text_raw_tp = """
RAW_TRACEPOINT_PROBE(sched_wakeup)
{
    // TP_PROTO(struct task_struct *p)
    struct task_struct *p = (struct task_struct *)ctx->args[0];
    return trace_wakeup(ctx, p);
}

RAW_TRACEPOINT_PROBE(sched_switch)
{
    // TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next)
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    return trace_offcpu(prev);
}
"""

is_support_raw_tp = BPF.support_raw_tracepoint()
if is_support_raw_tp:
    bpf_text = bpf_text.replace('CTX_TYPE', 'struct bpf_raw_tracepoint_args')
    bpf_text += bpf_text_raw_tp
else:
    bpf_text = bpf_text.replace('CTX_TYPE', 'struct pt_regs')
    bpf_text += bpf_text_kprobe

# code substitutions
if BPF.kernel_struct_has_field(b'task_struct', b'__state') == 1:
    bpf_text = bpf_text.replace('STATE_FIELD', '__state')
else:
    bpf_text = bpf_text.replace('STATE_FIELD', 'state')
if min_us == 0:
    bpf_text = bpf_text.replace('FILTER_US', '0')
else:
    bpf_text = bpf_text.replace('FILTER_US', 'delta_us <= %s' % str(min_us))

if args.tid:
    bpf_text = bpf_text.replace('FILTER_PID', 'pid != %s' % args.tid)
else:
    bpf_text = bpf_text.replace('FILTER_PID', '0')

if args.pid:
    bpf_text = bpf_text.replace('FILTER_TGID', 'tgid != %s' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER_TGID', '0')

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("%-8s [%03d] %-16s %-7s %d" % (strftime("%H:%M:%S"), cpu, event.task.decode('utf-8', 'replace'), event.pid, event.delta_us))

max_pid = int(open("/proc/sys/kernel/pid_max").read())

# load BPF program
b = BPF(text=bpf_text, cflags=["-DMAX_PID=%d" % max_pid])
if not is_support_raw_tp:
    b.attach_kprobe(event="ttwu_do_wakeup", fn_name="trace_ttwu_do_wakeup")
    b.attach_kprobe(event_re="^finish_task_switch$|^finish_task_switch\.isra\.\d$",
                    fn_name="trace_run")

print("Tracing sleep latency higher than %d us" % min_us)
print("%-8s %-5s %-16s %-7s %s" % ("TIME","CPU", "COMM", "TID", "LAT(us)"))

# read events
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
