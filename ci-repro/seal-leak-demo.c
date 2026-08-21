// SPDX-License-Identifier: GPL-2.0
/* Positive control for the link_seal selftest leak audit.
 *
 * Creates a sealed iter/task link from the selftests' test_link_seal.bpf.o,
 * closes every fd, and exits WITHOUT unsealing. If sealing works, the link
 * must still be visible via BPF_LINK_GET_NEXT_ID after this process dies.
 * This proves that an empty link list after test_progs is a real result,
 * not a vacuous one.
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#ifndef BPF_F_LINK_SEALED
#define BPF_F_LINK_SEALED (1U << 31)
#endif

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_link_create_opts, opts, .flags = BPF_F_LINK_SEALED);
	struct bpf_link_info info = {};
	__u32 len = sizeof(info);
	struct bpf_object *obj;
	struct bpf_program *prog, *p;
	int link_fd, err;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <test_link_seal.bpf.o>\n", argv[0]);
		return 1;
	}

	obj = bpf_object__open_file(argv[1], NULL);
	if (!obj) {
		fprintf(stderr, "open %s: %d\n", argv[1], -errno);
		return 1;
	}

	/* only load dump_task; the other progs need testmod kfuncs */
	prog = NULL;
	bpf_object__for_each_program(p, obj) {
		if (!strcmp(bpf_program__name(p), "dump_task"))
			prog = p;
		else
			bpf_program__set_autoload(p, false);
	}
	if (!prog || bpf_object__load(obj)) {
		fprintf(stderr, "load failed: %d\n", -errno);
		return 1;
	}

	link_fd = bpf_link_create(bpf_program__fd(prog), 0, BPF_TRACE_ITER, &opts);
	if (link_fd < 0) {
		fprintf(stderr, "sealed link_create failed: %d\n", link_fd);
		return 1;
	}

	err = bpf_link_get_info_by_fd(link_fd, &info, &len);
	if (err) {
		fprintf(stderr, "get_info failed: %d\n", err);
		return 1;
	}

	printf("leaked sealed link id=%u prog_id=%u\n", info.id, info.prog_id);
	close(link_fd);
	bpf_object__close(obj);
	/* exit without unsealing: the link must outlive this process */
	return 0;
}
