#!/usr/bin/python
#
# stackcount    Count kernel function calls and their stack traces.
#               For Linux, uses BCC, eBPF.
#
# USAGE: stackcount [-h] [-p PID] [-i INTERVAL] [-T] [-r] pattern
#
# The pattern is a string with optional '*' wildcards, similar to file
# globbing. If you'd prefer to use regular expressions, use the -r option.
#
# The current implementation uses an unrolled loop for x86_64, and was written
# as a proof of concept. This implementation should be replaced in the future
# with an appropriate bpf_ call, when available.
#
# Currently limited to a stack trace depth of 11 (maxdepth + 1).
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 12-Jan-2016	Brendan Gregg	Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
import signal

# arguments
examples = """examples:
    ./stackcount submit_bio       # count kernel stack traces for submit_bio
    ./stackcount ip_output        # count kernel stack traces for ip_output
    ./stackcount -s ip_output     # show symbol offsets
    ./stackcount -sv ip_output    # show offsets and raw addresses (verbose)
    ./stackcount 'tcp_send*'      # count stacks for funcs matching tcp_send*
    ./stackcount -r '^tcp_send.*' # same as above, using regular expressions
    ./stackcount -Ti 5 ip_output  # output every 5 seconds, with timestamps
    ./stackcount -p 185 ip_output # count ip_output stacks for PID 185 only
"""
parser = argparse.ArgumentParser(
    description="Count kernel function calls and their stack traces",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-i", "--interval", default=99999999,
    help="summary interval, seconds")
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-r", "--regexp", action="store_true",
    help="use regular expressions. Default is \"*\" wildcards only.")
parser.add_argument("-s", "--offset", action="store_true",
    help="show address offsets")
parser.add_argument("-v", "--verbose", action="store_true",
    help="show raw addresses")
parser.add_argument("pattern",
    help="search expression for kernel functions")
args = parser.parse_args()
pattern = args.pattern
if not args.regexp:
    pattern = pattern.replace('*', '.*')
    pattern = '^' + pattern + '$'
offset = args.offset
verbose = args.verbose
debug = 0
maxdepth = 10    # and MAXDEPTH

# signal handler
def signal_ignore(signal, frame):
    print()

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

BPF_HASH(counts, int);
BPF_STACK_TRACE(stack_traces, 1024);

int trace_count(struct pt_regs *ctx) {
    FILTER
    int key = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
    u64 zero = 0;
    u64 *val = counts.lookup_or_init(&key, &zero);
    (*val)++;
    return 0;
}
"""
if args.pid:
    bpf_text = bpf_text.replace('FILTER',
        ('u32 pid; pid = bpf_get_current_pid_tgid(); ' +
        'if (pid != %s) { return 0; }') % (args.pid))
else:
    bpf_text = bpf_text.replace('FILTER', '')
if debug:
    print(bpf_text)
b = BPF(text=bpf_text)
b.attach_kprobe(event_re=pattern, fn_name="trace_count")
matched = b.num_open_kprobes()
if matched == 0:
    print("0 functions matched by \"%s\". Exiting." % args.pattern)
    exit()

# header
print("Tracing %d functions for \"%s\"... Hit Ctrl-C to end." %
    (matched, args.pattern))

def print_frame(addr):
    print("  ", end="")
    if verbose:
        print("%-16x " % addr, end="")
    if offset:
        print("%s" % b.ksymaddr(addr))
    else:
        print("%s" % b.ksym(addr))

# output
exiting = 0 if args.interval else 1
while (1):
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting = 1
        # as cleanup can take many seconds, trap Ctrl-C:
        signal.signal(signal.SIGINT, signal_ignore)

    print()
    if args.timestamp:
        print("%-8s\n" % strftime("%H:%M:%S"), end="")

    counts = b["counts"]
    stack_traces = b["stack_traces"]
    for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
        for addr in stack_traces.walk(k.value):
            print_frame(addr)
        print("    %d\n" % v.value)
    counts.clear()

    if exiting:
        print("Detaching...")
        exit()
