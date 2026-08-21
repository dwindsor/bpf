#!/bin/bash
# Guest init for CI-repro v6: ramfs mounted at /dev/shm (no xattr support
# in initxattrs path); init_inode_xattr tests must SKIP gracefully.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
RES=/home/dave/src/kernelsource.google.com/bpf-next/ci-repro/result-v6-ramfs.txt

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mkdir -p /dev/shm
mount -t ramfs ramfs /dev/shm
mount -t tmpfs tmpfs /run
mount -t tmpfs tmpfs /tmp
mount -t cgroup2 cgroup2 /sys/fs/cgroup 2>/dev/null
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null
mount -t tracefs tracefs /sys/kernel/debug/tracing 2>/dev/null
mount -t bpf bpf /sys/fs/bpf 2>/dev/null

{
	echo "=== uname: $(uname -r)"
	echo "=== /dev/shm fstype: $(findmnt -n -o FSTYPE -T /dev/shm 2>/dev/null || awk '$2=="/dev/shm"{print $3}' /proc/mounts)"
	cd /home/dave/src/kernelsource.google.com/bpf-next/tools/testing/selftests/bpf || exit
	./test_progs -t fs_kfuncs
	echo "=== test_progs rc=$?"
} > "$RES" 2>&1

sync
echo o > /proc/sysrq-trigger
sleep 30
