#!/bin/bash
# Boot the freshly built kernel with a 9p rootfs (host / passthrough),
# replicating the kernel-patches BPF CI vmtest environment.
# Usage: run-vm.sh <init-script> <console-log>
set -eu

KERNEL=/home/dave/src/kernelsource.google.com/bpf-next/arch/x86/boot/bzImage
INIT=$1
LOG=$2

timeout --foreground 900 qemu-system-x86_64 \
	-nodefaults -no-reboot -nographic \
	-enable-kvm -cpu host -smp 4 -m 4G \
	-serial mon:stdio \
	-kernel "$KERNEL" \
	-fsdev local,id=fsdev0,path=/,security_model=none,multidevs=remap \
	-device virtio-9p-pci,fsdev=fsdev0,mount_tag=/dev/root \
	-append "rootfstype=9p rootflags=trans=virtio,cache=mmap,msize=1048576 rw console=ttyS0 earlyprintk=serial loglevel=4 raid=noautodetect init=$INIT panic=-1 lsm=selinux,bpf" \
	> "$LOG" 2>&1
