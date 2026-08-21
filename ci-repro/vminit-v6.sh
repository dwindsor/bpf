#!/bin/bash
# Guest init for CI-repro v6: tmpfs mounted at /dev/shm (like BPF CI).
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
RES=/home/dave/src/kernelsource.google.com/bpf-next/ci-repro/result-v6.txt

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
	echo "=== rootfs: $(findmnt -n -o FSTYPE / 2>/dev/null || awk '$2=="/"{print $3}' /proc/mounts)"
	echo "=== /dev/shm: $(awk '$2=="/dev/shm"{print $3}' /proc/mounts)"
	cd /home/dave/src/kernelsource.google.com/bpf-next/tools/testing/selftests/bpf || exit
	./test_progs -t fs_kfuncs
	echo "=== test_progs rc=$?"
} > "$RES" 2>&1

sync
echo o > /proc/sysrq-trigger
sleep 30
