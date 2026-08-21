#!/bin/bash
# Rebase v6 onto latest origin/master, rebuild, retest, and only roll
# patches if all selftest scenarios pass. Never sends anything.
# Full log in ci-repro/v6-rerun.log
cd /home/dave/src/kernelsource.google.com/bpf-next || exit 1
exec > >(tee ci-repro/v6-rerun.log) 2>&1
set -x

# Save the finished cover letter body before regenerating
awk '/^Subject: \[PATCH v6/,/^v5: https/' v6/0000-cover-letter.patch > /tmp/v6-cover-body.txt
[ -s /tmp/v6-cover-body.txt ] || { echo "!!! could not save cover letter body"; exit 1; }

if ! git rebase --autostash origin/master; then
	echo "!!! REBASE CONFLICT - aborting rebase, branch left at old base"
	git rebase --abort
	exit 1
fi
git log --oneline origin/master..HEAD

make -j"$(nproc)" bzImage || { echo "!!! KERNEL BUILD FAILED"; exit 1; }
make -C tools/testing/selftests/bpf -j"$(nproc)" BPF_STRICT_BUILD=0 test_progs || { echo "!!! SELFTEST BUILD FAILED"; exit 1; }

./ci-repro/run-vm.sh "$(pwd)/ci-repro/vminit-v6.sh" ci-repro/console-v6.log
./ci-repro/run-vm.sh "$(pwd)/ci-repro/vminit-v6-ramfs.sh" ci-repro/console-v6-ramfs.log
./ci-repro/run-vm.sh "$(pwd)/ci-repro/vminit-v6-skip2.sh" ci-repro/console-v6-skip2.log

set +x
echo "====== RESULTS tmpfs ======";  cat ci-repro/result-v6.txt
echo "====== RESULTS ramfs ======";  cat ci-repro/result-v6-ramfs.txt
echo "====== RESULTS 9p-skip ====="; cat ci-repro/result-v6-skip.txt

fail=0
grep -q "init_inode_xattr:OK" ci-repro/result-v6.txt || { echo "!!! tmpfs: init_inode_xattr not OK"; fail=1; }
grep -q "init_inode_xattr_slot_limit:OK" ci-repro/result-v6.txt || { echo "!!! tmpfs: slot_limit not OK"; fail=1; }
grep -q "test_progs rc=0" ci-repro/result-v6.txt || { echo "!!! tmpfs: test_progs rc != 0"; fail=1; }
grep -q "init_inode_xattr:SKIP" ci-repro/result-v6-ramfs.txt || { echo "!!! ramfs: init_inode_xattr did not SKIP"; fail=1; }
grep -q "init_inode_xattr_slot_limit:SKIP" ci-repro/result-v6-ramfs.txt || { echo "!!! ramfs: slot_limit did not SKIP"; fail=1; }
grep -q "test_progs rc=0" ci-repro/result-v6-ramfs.txt || { echo "!!! ramfs: test_progs rc != 0"; fail=1; }
grep -q "init_inode_xattr:SKIP" ci-repro/result-v6-skip.txt || { echo "!!! 9p: init_inode_xattr did not SKIP"; fail=1; }
grep -q "init_inode_xattr_slot_limit:SKIP" ci-repro/result-v6-skip.txt || { echo "!!! 9p: slot_limit did not SKIP"; fail=1; }
grep -q "test_progs rc=0" ci-repro/result-v6-skip.txt || { echo "!!! 9p: test_progs rc != 0"; fail=1; }

if [ "$fail" -ne 0 ]; then
	echo "====== SELFTESTS FAILED - NOT ROLLING PATCHES ======"
	exit 1
fi
echo "====== ALL SELFTEST SCENARIOS PASSED ======"
set -x

rm -rf v6
git format-patch --subject-prefix="PATCH v6 bpf-next" --cover-letter \
	--base="$(git rev-parse origin/master)" -o v6 origin/master..HEAD

python3 - <<'PYEOF'
body = open('/tmp/v6-cover-body.txt').read().rstrip('\n')
path = 'v6/0000-cover-letter.patch'
cover = open(path).read()
old = 'Subject: [PATCH v6 bpf-next 0/4] *** SUBJECT HERE ***\n\n*** BLURB HERE ***'
assert old in cover, 'cover letter template not found'
open(path, 'w').write(cover.replace(old, body))
print('cover letter spliced OK')
PYEOF

set +x
./scripts/checkpatch.pl v6/000[1-4]*.patch | grep -E "total:|WARNING|ERROR"
echo "====== V6 RERUN COMPLETE rc=0 - patches rolled in v6/, NOTHING SENT ======"
