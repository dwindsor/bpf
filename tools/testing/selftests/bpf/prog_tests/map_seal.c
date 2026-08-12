// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 David Windsor */
#include <test_progs.h>
#include "test_map_seal.skel.h"

/* Drop the self-reference held by a sealed map, via a bpf_testmod kfunc, so the
 * map can be freed once its last fd goes away. Without this every run of this
 * test would leak a map until the machine reboots.
 */
static int force_unseal(struct test_map_seal *skel, int map_fd)
{
	struct { int map_fd; } args = { .map_fd = map_fd };
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.ctx_in = &args,
		.ctx_size_in = sizeof(args),
	);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.unseal_map),
				     &opts);
	if (err)
		return err;
	return opts.retval;
}

static int create_map(__u32 extra_flags)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = extra_flags);

	return bpf_map_create(BPF_MAP_TYPE_ARRAY, "seal_test", 4, 8, 4, &opts);
}

/* Without BPF_F_SEALED a map is writable and freezable as usual. */
static void test_unsealed_map(void)
{
	__u32 key = 0;
	__u64 val = 1;
	int fd, err;

	fd = create_map(0);
	if (!ASSERT_GE(fd, 0, "create"))
		return;

	err = bpf_map_update_elem(fd, &key, &val, 0);
	ASSERT_OK(err, "update");

	err = bpf_map_freeze(fd);
	ASSERT_OK(err, "freeze");

	/* frozen: writes from user space are refused from here on */
	err = bpf_map_update_elem(fd, &key, &val, 0);
	ASSERT_EQ(err, -EPERM, "update_after_freeze");

	close(fd);
}

/* A sealed map is frozen from creation and can never be written or re-frozen. */
static void test_sealed_map(struct test_map_seal *skel)
{
	struct bpf_map_info info = {};
	__u32 len = sizeof(info);
	__u32 key = 0, id;
	int fd, fd2, err;
	__u64 val = 1;

	fd = create_map(BPF_F_SEALED);
	if (!ASSERT_GE(fd, 0, "create_sealed"))
		return;

	/* frozen from the outset: there was never a writable window */
	err = bpf_map_update_elem(fd, &key, &val, 0);
	ASSERT_EQ(err, -EPERM, "update_rejected");

	err = bpf_map_delete_elem(fd, &key);
	ASSERT_EQ(err, -EPERM, "delete_rejected");

	/* already frozen, so freezing again reports -EBUSY, not -EPERM */
	err = bpf_map_freeze(fd);
	ASSERT_EQ(err, -EBUSY, "freeze_rejected");

	/* reads still work */
	err = bpf_map_lookup_elem(fd, &key, &val);
	ASSERT_OK(err, "lookup");

	err = bpf_map_get_info_by_fd(fd, &info, &len);
	if (!ASSERT_OK(err, "get_info"))
		goto cleanup;
	if (!ASSERT_TRUE(info.map_flags & BPF_F_SEALED, "flag_reported"))
		goto cleanup;
	id = info.id;

	/* closing the last fd must not tear the map down */
	close(fd);
	fd = -1;

	fd2 = bpf_map_get_fd_by_id(id);
	if (!ASSERT_GE(fd2, 0, "alive_after_close"))
		return;

	err = bpf_map_update_elem(fd2, &key, &val, 0);
	ASSERT_EQ(err, -EPERM, "update_rejected_after_close");

	fd = fd2;
cleanup:
	if (fd < 0)
		return;

	err = force_unseal(skel, fd);
	if (!ASSERT_OK(err, "force_unseal")) {
		close(fd);
		return;
	}

	memset(&info, 0, sizeof(info));
	len = sizeof(info);
	err = bpf_map_get_info_by_fd(fd, &info, &len);
	if (ASSERT_OK(err, "get_info_after_unseal"))
		id = info.id;
	close(fd);

	/* the map is freed from a workqueue, so poll for it to disappear */
	for (int i = 0; i < 100; i++) {
		fd2 = bpf_map_get_fd_by_id(id);
		if (fd2 < 0)
			break;
		close(fd2);
		usleep(10000);
	}
	ASSERT_EQ(fd2, -ENOENT, "freed_after_unseal");
}

/* Sealing is limited to the map types BPF_MAP_FREEZE supports. A map with a
 * spin lock in its value is not freezable, so it must not be sealable either.
 */
static void test_seal_unsupported(struct test_map_seal *skel)
{
	int fd;

	fd = bpf_map__fd(skel->maps.lock_map);
	if (!ASSERT_GE(fd, 0, "lock_map_fd"))
		return;

	/* the same map layout, but asking for a seal, must fail */
	fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "seal_lock", 4,
			    bpf_map__value_size(skel->maps.lock_map), 1,
			    &(struct bpf_map_create_opts){
				.sz = sizeof(struct bpf_map_create_opts),
				.map_flags = BPF_F_SEALED,
				.btf_fd = bpf_object__btf_fd(skel->obj),
				.btf_key_type_id = bpf_map__btf_key_type_id(skel->maps.lock_map),
				.btf_value_type_id = bpf_map__btf_value_type_id(skel->maps.lock_map),
			    });
	if (!ASSERT_LT(fd, 0, "seal_lock_map_rejected")) {
		close(fd);
		return;
	}
	ASSERT_EQ(fd, -EOPNOTSUPP, "seal_lock_map_err");
}

void test_map_seal(void)
{
	struct test_map_seal *skel;

	skel = test_map_seal__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	if (test__start_subtest("unsealed"))
		test_unsealed_map();
	if (test__start_subtest("sealed"))
		test_sealed_map(skel);
	if (test__start_subtest("unsupported"))
		test_seal_unsupported(skel);

	test_map_seal__destroy(skel);
}
