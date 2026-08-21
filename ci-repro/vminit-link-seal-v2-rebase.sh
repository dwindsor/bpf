#!/bin/bash
# Same as vminit-link-seal-v2.sh, but copy bpf_testmod.ko onto tmpfs first.
# After the rebase rebuild the module is 1.2M, which is larger than the 9p
# msize=1M used by run-vm-seal-v2.sh; finit_module then fails with ENOEXEC
# (Invalid module format) when it reads the truncated 9p mapping.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
RES=/home/dave/src/kernelsource.google.com/bpf-next/ci-repro/result-link-seal-v2-rebase.txt

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
	cd /home/dave/seal-v2/tools/testing/selftests/bpf || exit

	# Avoid 9p truncating bpf_testmod.ko (1.2M) at msize=1M.
	cp ./bpf_testmod.ko /tmp/bpf_testmod.ko
	mount --bind /tmp/bpf_testmod.ko ./bpf_testmod.ko
	echo "=== bpf_testmod.ko size: $(wc -c < /tmp/bpf_testmod.ko)"
	insmod ./bpf_testmod.ko
	echo "=== insmod rc=$? dmesg:"
	dmesg | tail -20
	rmmod bpf_testmod 2>/dev/null

	echo "=== [1] links before test:"
	bpftool link show
	echo "=== link count before: $(bpftool link show | grep -c '^[0-9]')"

	echo "=== [2] running test_progs -t link_seal"
	./test_progs -v -t link_seal
	echo "=== test_progs rc=$?"

	echo "=== [3] links after test (must be empty):"
	bpftool link show
	echo "=== link count after: $(bpftool link show | grep -c '^[0-9]')"

	echo "=== [4] positive control: sealed link without unseal"
	insmod ./bpf_testmod.ko
	DEMO_OUT=$(/home/dave/src/kernelsource.google.com/bpf-next/ci-repro/seal-leak-demo \
		./test_link_seal.bpf.o)
	echo "=== demo rc=$? output: $DEMO_OUT"
	LEAK_ID=$(echo "$DEMO_OUT" | sed -n 's/.*link id=\([0-9]*\).*/\1/p')

	echo "=== [5] links after control (leaked sealed link must persist):"
	bpftool link show
	echo "=== link count after control: $(bpftool link show | grep -c '^[0-9]')"

	echo "=== [6] try to detach leaked sealed link id=$LEAK_ID via bpftool:"
	bpftool link detach id "$LEAK_ID"
	echo "=== detach rc=$? (must fail with EPERM)"
	bpftool link show
	echo "=== link count final: $(bpftool link show | grep -c '^[0-9]')"
} > "$RES" 2>&1

sync
echo o > /proc/sysrq-trigger
sleep 30
