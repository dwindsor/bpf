// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Cisco Systems, Inc. */

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_tracing.h>
#include "bpf_kfuncs.h"

char _license[] SEC("license") = "GPL";

__u32 monitored_pid;
bool armed;
bool hook_ran;
int set_result = -1;
int forbidden_result = -1;

const char xattr_name[] = "security.bpf.file_test";
const char forbidden_name[] = "security.selinux";
char xattr_value[] = "file-backed-bpf-xattr";

SEC("lsm.s/file_open")
int BPF_PROG(test_set_file_xattr, struct file *file)
{
	struct bpf_dynptr value;
	__u32 pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != monitored_pid || !armed)
		return 0;

	/* One shot. The kfunc itself can cause filesystem activity and the test
	 * process opens more files while reading results. */
	armed = false;
	hook_ran = true;

	if (bpf_dynptr_from_mem(xattr_value, sizeof(xattr_value), 0, &value)) {
		set_result = -EINVAL;
		return 0;
	}

	set_result = bpf_set_file_xattr(file, xattr_name, &value, 0);
	forbidden_result = bpf_set_file_xattr(file, forbidden_name, &value, 0);

	return 0;
}
