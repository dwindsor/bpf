#!/bin/bash
# Guest init: prove the link_seal selftest (v2 patches, built in ~/seal-v2)
# leaves no links behind, and that the testmod force-unseal kfunc is the
# reason why (positive control: a sealed link with no unseal persists).
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
RES=/home/dave/src/kernelsource.google.com/bpf-next/ci-repro/result-link-seal-v2.txt

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
	# testmod must be loaded so libbpf can resolve the kfunc extern in
	# test_link_seal.bpf.o (the demo itself never calls the kfunc)
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
