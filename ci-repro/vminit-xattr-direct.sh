#!/bin/bash
# Guest init: run fs_kfuncs selftests (incl. init_inode_xattr) on the
# wt-xattr-direct kernel.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
RES=/home/dave/src/kernelsource.google.com/bpf-next/ci-repro/result-xattr-direct.txt

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mkdir -p /dev/shm
mount -t tmpfs tmpfs /dev/shm
mount -t tmpfs tmpfs /run
mount -t tmpfs tmpfs /tmp
mount -t cgroup2 cgroup2 /sys/fs/cgroup 2>/dev/null
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null
mount -t tracefs tracefs /sys/kernel/debug/tracing 2>/dev/null
mount -t bpf bpf /sys/fs/bpf 2>/dev/null

{
	echo "=== uname: $(uname -r)"
	cd /home/dave/src/kernelsource.google.com/wt-xattr-direct/tools/testing/selftests/bpf || exit
	./test_progs -t fs_kfuncs
	echo "=== test_progs rc=$?"
} > "$RES" 2>&1

sync
echo o > /proc/sysrq-trigger
sleep 30
