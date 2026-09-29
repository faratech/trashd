#!/usr/bin/env bash
# End-to-end checks against locally built artifacts, never installed trashd.
# Usage: sudo ./tests/integration.sh [target/debug|target/release]
# Optional online self-update check: TRASHD_TEST_NETWORK=1 sudo -E ./tests/integration.sh
set -euo pipefail

if [[ "${TRASHD_TEST_SANDBOX:-}" != "1" ]]; then
    REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
    exec env TRASH_BYPASS=1 python3 "$REPO/tests/sandbox.py" \
        --build-dir "${1:-$REPO/target/debug}" -- /bin/bash /tests/integration.sh
fi
# Also reject a stale or manually inherited environment marker.
python3 -c 'import sys; sys.path.insert(0, "/tests"); from sandbox import require_sandbox; require_sandbox()'
TRASH=/opt/trashd/bin/trash
SHIM=/opt/trashd/bin/trashd-rm
EXEC=/opt/trashd/bin/trashd-exec
PRELOAD=/opt/trashd/lib/libtrashd_preload.so
for artifact in "$TRASH" "$SHIM" "$EXEC" "$PRELOAD"; do
    [[ -f "$artifact" ]] || { echo "Missing built artifact: $artifact" >&2; exit 1; }
done
[[ "$(command -v rm)" == /opt/trashd/bin/rm ]] || { echo 'Built PATH shim missing' >&2; exit 1; }
if /usr/bin/rm --version | grep >/dev/null trashd; then
    echo 'Runtime /usr/bin/rm is another shim; cannot test explicit permanent bypass' >&2
    exit 1
fi
unset LD_PRELOAD TRASHD_SECCOMP_ACTIVE
export TRASH_BYPASS=0
trash() { "$TRASH" "$@"; }
preload_python() { LD_PRELOAD="$PRELOAD" python3 "$@"; }

PASS=0
FAIL=0
SKIP=0
TESTS=()

pass() { PASS=$((PASS + 1)); TESTS+=("PASS: $1"); }
fail() { FAIL=$((FAIL + 1)); TESTS+=("FAIL: $1 — $2"); }

skip() { SKIP=$((SKIP + 1)); TESTS+=("SKIP: $1"); }

# Clean state
trash empty -y >/dev/null

# -----------------------------------------------------------------------
# Layer 1: PATH shim
# -----------------------------------------------------------------------
# /tmp is in never_trash so use home
echo "shim_test" > /home/test/trashd_it_shim.txt
rm /home/test/trashd_it_shim.txt
if trash ls 2>&1 | grep >/dev/null "trashd_it_shim"; then
    pass "Layer 1: shim trashes file"
else
    fail "Layer 1: shim trashes file" "not found in trash"
fi
trash undo >/dev/null 2>&1
rm --permanent /home/test/trashd_it_shim.txt 2>/dev/null

# -----------------------------------------------------------------------
# Layer 2: LD_PRELOAD
# -----------------------------------------------------------------------
echo "preload_test" > /home/test/trashd_it_preload.txt
preload_python -c "import os; os.remove('/home/test/trashd_it_preload.txt')" 2>/dev/null
if trash ls 2>&1 | grep >/dev/null "trashd_it_preload"; then
    pass "Layer 2: LD_PRELOAD trashes python unlink"
else
    fail "Layer 2: LD_PRELOAD trashes python unlink" "not found in trash"
fi
trash empty -y >/dev/null 2>&1

# -----------------------------------------------------------------------
# Bypass: --permanent
# -----------------------------------------------------------------------
echo "perm" > /home/test/trashd_it_perm.txt
rm --permanent /home/test/trashd_it_perm.txt
if trash ls 2>&1 | grep >/dev/null "trashd_it_perm"; then
    fail "Bypass: --permanent" "file found in trash (should not be)"
else
    pass "Bypass: --permanent"
fi

# -----------------------------------------------------------------------
# Bypass: TRASH_BYPASS=1
# -----------------------------------------------------------------------
echo "bypass" > /home/test/trashd_it_bypass.txt
TRASH_BYPASS=1 rm /home/test/trashd_it_bypass.txt
if trash ls 2>&1 | grep >/dev/null "trashd_it_bypass"; then
    fail "Bypass: TRASH_BYPASS=1" "file found in trash"
else
    pass "Bypass: TRASH_BYPASS=1"
fi

# -----------------------------------------------------------------------
# trash undo
# -----------------------------------------------------------------------
echo "undo_test" > /home/test/trashd_it_undo.txt
rm /home/test/trashd_it_undo.txt
trash undo >/dev/null 2>&1
if [ -f /home/test/trashd_it_undo.txt ]; then
    pass "trash undo restores file"
else
    fail "trash undo restores file" "file not restored"
fi
rm --permanent /home/test/trashd_it_undo.txt 2>/dev/null

# -----------------------------------------------------------------------
# trash restore with --to
# -----------------------------------------------------------------------
echo "restore_to" > /home/test/trashd_it_rto.txt
rm /home/test/trashd_it_rto.txt
trash restore trashd_it_rto.txt --to /home/test/trashd_it_rto_alt.txt >/dev/null 2>&1
if [ -f /home/test/trashd_it_rto_alt.txt ]; then
    pass "trash restore --to"
else
    fail "trash restore --to" "file not at alternate path"
fi
rm --permanent /home/test/trashd_it_rto_alt.txt 2>/dev/null

# -----------------------------------------------------------------------
# trash purge
# -----------------------------------------------------------------------
echo "purge_me" > /home/test/trashd_it_purge.txt
rm /home/test/trashd_it_purge.txt
trash purge trashd_it_purge.txt >/dev/null 2>&1
if trash ls 2>&1 | grep >/dev/null "trashd_it_purge"; then
    fail "trash purge" "entry still in trash"
else
    pass "trash purge"
fi

# -----------------------------------------------------------------------
# trash empty -y
# -----------------------------------------------------------------------
echo "e1" > /home/test/trashd_it_e1.txt
echo "e2" > /home/test/trashd_it_e2.txt
rm /home/test/trashd_it_e1.txt /home/test/trashd_it_e2.txt
trash empty -y >/dev/null 2>&1
if [ "$(trash ls 2>&1)" = "Trash is empty." ]; then
    pass "trash empty -y"
else
    fail "trash empty -y" "trash not empty after empty"
fi

# -----------------------------------------------------------------------
# .git/* pattern (infix glob)
# -----------------------------------------------------------------------
mkdir -p /home/test/trashd_it_repo/.git/objects
echo "obj" > /home/test/trashd_it_repo/.git/objects/test_obj
preload_python -c "import os; os.remove('/home/test/trashd_it_repo/.git/objects/test_obj')" 2>/dev/null
if trash ls 2>&1 | grep >/dev/null "test_obj"; then
    fail ".git/* skip pattern" "git object was trashed"
else
    pass ".git/* skip pattern"
fi
rm -rf /home/test/trashd_it_repo 2>/dev/null

# -----------------------------------------------------------------------
# Restore conflict
# -----------------------------------------------------------------------
echo "v1" > /home/test/trashd_it_conflict.txt
rm /home/test/trashd_it_conflict.txt
echo "v2" > /home/test/trashd_it_conflict.txt
OUTPUT=$(trash restore trashd_it_conflict.txt 2>&1 || true)
if echo "$OUTPUT" | grep -qiE "already exists|conflict"; then
    pass "Restore conflict detection"
else
    fail "Restore conflict detection" "got: $OUTPUT"
fi
rm --permanent /home/test/trashd_it_conflict.txt 2>/dev/null
trash empty -y >/dev/null 2>&1

# -----------------------------------------------------------------------
# Duplicate filename unique IDs
# -----------------------------------------------------------------------
echo "first" > /home/test/trashd_it_dup.txt
rm /home/test/trashd_it_dup.txt
echo "second" > /home/test/trashd_it_dup.txt
rm /home/test/trashd_it_dup.txt
# || true: grep -c exits 1 on zero matches, and set -e would abort the whole
# suite right when this test FAILS — hiding the summary (#48).
COUNT=$(trash ls 2>&1 | grep -c "trashd_it_dup" || true)
if [ "$COUNT" -ge 2 ]; then
    pass "Duplicate filenames get unique IDs"
else
    fail "Duplicate filenames get unique IDs" "got $COUNT entries, expected 2+"
fi
trash empty -y >/dev/null 2>&1

# -----------------------------------------------------------------------
# trash fsck
# -----------------------------------------------------------------------
echo "orphan" > ~/.local/share/Trash/files/trashd_it_orphan
if trash fsck 2>&1 | grep >/dev/null "orphan"; then
    pass "trash fsck detects orphans"
else
    fail "trash fsck detects orphans" "orphan not detected"
fi
# --permanent: the shim now REFUSES plain rm on paths inside the trash
# (audit #8) — deleting trash internals requires the explicit bypass.
rm -f --permanent ~/.local/share/Trash/files/trashd_it_orphan

# -----------------------------------------------------------------------
# seccomp layer end-to-end: real rm under trashd-exec must land in trash
# via the fd-pinned supervisor (TRASHD_SECCOMP_ACTIVE makes the preload
# defer so this exercises Layer 4 specifically).
# -----------------------------------------------------------------------
echo "sec" > /home/test/trashd_it_sec.txt
if [ -x "$EXEC" ] && [ -x /usr/bin/rm ]; then
    # seccomp(2) allows only ONE NEW_LISTENER filter per chain: inside an
    # already-filtered environment (some CI sandboxes/containers) the child's
    # install fails with EBUSY and trashd-exec warns before fallback.
    # Skip unless REQUIRE_SECCOMP explicitly requires listener coverage.
    PARENT_F=$(grep -s "^Seccomp_filters:" /proc/self/status | tr -dc "0-9")
    CHILD_F=$(timeout 10 "$EXEC" \
        /bin/sh -c 'grep -s "^Seccomp_filters:" /proc/self/status | tr -dc "0-9"' 2>/dev/null)
    if [ -n "$CHILD_F" ] && [ "$CHILD_F" = "$PARENT_F" ]; then
        if [[ "${REQUIRE_SECCOMP:-0}" == "1" ]]; then
            fail "seccomp e2e" "new listener unavailable on required host"
        else
            skip "seccomp e2e (kernel refused a new notification listener)"
        fi
    else
        timeout 20 "$EXEC" \
            /usr/bin/rm -f /home/test/trashd_it_sec.txt >/dev/null 2>&1
        if [ ! -f /home/test/trashd_it_sec.txt ] && trash ls 2>&1 | grep >/dev/null "trashd_it_sec"; then
            pass "seccomp supervisor trashes rm under trashd-exec"
        else
            fail "seccomp supervisor trashes rm under trashd-exec" "file not trashed"
        fi
    fi
else
    fail "seccomp e2e" "built wrapper or system rm missing"
fi

# -----------------------------------------------------------------------
# trash restore --force (auto-rename on conflict)
# -----------------------------------------------------------------------
echo "force_test" > /home/test/trashd_it_force.txt
rm /home/test/trashd_it_force.txt
echo "blocker" > /home/test/trashd_it_force.txt
trash restore trashd_it_force.txt --force >/dev/null 2>&1
if [ -f /home/test/trashd_it_force.txt.1 ]; then
    pass "trash restore --force auto-renames"
else
    fail "trash restore --force auto-renames" "renamed file not found"
fi
rm --permanent /home/test/trashd_it_force.txt /home/test/trashd_it_force.txt.1 2>/dev/null
trash empty -y >/dev/null 2>&1

# -----------------------------------------------------------------------
# trash restore --all (batch restore)
# -----------------------------------------------------------------------
echo "batch1" > /home/test/trashd_it_b1.py
echo "batch2" > /home/test/trashd_it_b2.py
rm /home/test/trashd_it_b1.py /home/test/trashd_it_b2.py
OUTPUT=$(trash restore '*.py' --all 2>&1 || true)
if echo "$OUTPUT" | grep >/dev/null "Restored:" && [ -f /home/test/trashd_it_b1.py ] && [ -f /home/test/trashd_it_b2.py ]; then
    pass "trash restore --all batch restore"
else
    fail "trash restore --all batch restore" "files not restored"
fi
rm --permanent /home/test/trashd_it_b1.py /home/test/trashd_it_b2.py 2>/dev/null
trash empty -y >/dev/null 2>&1

# -----------------------------------------------------------------------
# trash ls --after time filter
# -----------------------------------------------------------------------
echo "recent" > /home/test/trashd_it_recent.txt
rm /home/test/trashd_it_recent.txt
if trash ls --after 1h 2>&1 | grep >/dev/null "trashd_it_recent"; then
    pass "trash ls --after shows recent items"
else
    fail "trash ls --after shows recent items" "recent file not shown"
fi
trash empty -y >/dev/null 2>&1

# -----------------------------------------------------------------------
# trash ls --json
# -----------------------------------------------------------------------
echo "jsontest" > /home/test/trashd_it_json.txt
rm /home/test/trashd_it_json.txt
if trash ls --json 2>&1 | grep >/dev/null '"id"'; then
    pass "trash ls --json outputs JSON"
else
    fail "trash ls --json outputs JSON" "no JSON output"
fi
trash empty -y >/dev/null 2>&1

# -----------------------------------------------------------------------
# trash config show
# -----------------------------------------------------------------------
if trash config show 2>&1 | grep >/dev/null "never_trash"; then
    pass "trash config show"
else
    fail "trash config show" "config not shown"
fi

# -----------------------------------------------------------------------
# trash config get/set
# -----------------------------------------------------------------------
ORIGINAL=$(trash config get retention.max_age_days 2>&1)
trash config set retention.max_age_days 99 >/dev/null 2>&1
NEW_VAL=$(trash config get retention.max_age_days 2>&1)
if [ "$NEW_VAL" = "99" ]; then
    pass "trash config set/get"
else
    fail "trash config set/get" "expected 99, got $NEW_VAL"
fi
# Reset
trash config reset -y >/dev/null 2>&1

# -----------------------------------------------------------------------
# trash compress (dry run)
# -----------------------------------------------------------------------
echo "compress_test_data_repeated" > /home/test/trashd_it_comp.txt
for i in $(seq 1 100); do echo "line $i of repeated data for compression test" >> /home/test/trashd_it_comp.txt; done
rm /home/test/trashd_it_comp.txt
# Items just trashed won't be compressed (--older 0d would be needed)
OUTPUT=$(trash compress --older 0d --dry-run 2>&1)
if echo "$OUTPUT" | grep -qE "would be compressed|Nothing to compress"; then
    pass "trash compress --dry-run"
else
    fail "trash compress --dry-run" "unexpected output: $OUTPUT"
fi
trash empty -y >/dev/null 2>&1

# -----------------------------------------------------------------------
# Permissions preserved
# -----------------------------------------------------------------------
echo "secret" > /home/test/trashd_it_perms.txt
chmod 600 /home/test/trashd_it_perms.txt
rm /home/test/trashd_it_perms.txt
trash undo >/dev/null 2>&1
PERMS=$(stat -c %a /home/test/trashd_it_perms.txt 2>/dev/null)
if [ "$PERMS" = "600" ]; then
    pass "Permissions preserved on restore"
else
    fail "Permissions preserved on restore" "got $PERMS, expected 600"
fi
rm --permanent /home/test/trashd_it_perms.txt 2>/dev/null
trash empty -y >/dev/null 2>&1

# -----------------------------------------------------------------------
# trash self-update --check
# -----------------------------------------------------------------------
if [[ "${TRASHD_TEST_NETWORK:-0}" == "1" ]]; then
    if trash self-update --check 2>&1 | grep -qE "Up to date|Update available"; then
        pass "trash self-update --check"
    else
        fail "trash self-update --check" "unexpected output"
    fi
else
    skip "trash self-update --check (set TRASHD_TEST_NETWORK=1 to use network)"
fi

# -----------------------------------------------------------------------
# Local .trashd.toml override
# -----------------------------------------------------------------------
mkdir -p /home/test/trashd_it_local
echo 'only_trash = ["*.keep"]' > /home/test/trashd_it_local/.trashd.toml
echo "should trash" > /home/test/trashd_it_local/test.keep
echo "should skip" > /home/test/trashd_it_local/test.skip
preload_python -c "import os; os.remove('/home/test/trashd_it_local/test.keep')" 2>/dev/null
preload_python -c "import os; os.remove('/home/test/trashd_it_local/test.skip')" 2>/dev/null
KEEP_TRASHED=$(trash ls 2>&1 | grep -c "test.keep" || true)
SKIP_TRASHED=$(trash ls 2>&1 | grep -c "test.skip" || true)
if [ "$KEEP_TRASHED" -ge 1 ] && [ "$SKIP_TRASHED" -eq 0 ]; then
    pass "Local .trashd.toml only_trash override"
else
    fail "Local .trashd.toml only_trash override" "keep=$KEEP_TRASHED skip=$SKIP_TRASHED"
fi
rm -rf /home/test/trashd_it_local 2>/dev/null
trash empty -y >/dev/null 2>&1

# -----------------------------------------------------------------------
# Shim prompt/parser regressions
# -----------------------------------------------------------------------
if python3 /tests/shim_regression.py "$SHIM"; then
    pass "Shim repeated flags and prompt precedence"
else
    fail "Shim repeated flags and prompt precedence" "subprocess regression failed"
fi

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
echo ""
echo "========================================="
echo "  INTEGRATION TEST RESULTS"
echo "========================================="
for t in "${TESTS[@]}"; do
    echo "  $t"
done
echo ""
echo "  $PASS passed, $FAIL failed, $SKIP skipped"
echo "========================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
