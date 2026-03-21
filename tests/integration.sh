#!/usr/bin/env bash
# trashd end-to-end integration tests.
# Run after `sudo ./install.sh` with a new shell.
#
# Usage: sudo ./tests/integration.sh
set -euo pipefail
export TRASH_BYPASS=0

PASS=0
FAIL=0
TESTS=()

pass() { PASS=$((PASS + 1)); TESTS+=("PASS: $1"); }
fail() { FAIL=$((FAIL + 1)); TESTS+=("FAIL: $1 — $2"); }

source /etc/profile.d/trashd.sh 2>/dev/null || true

# Clean state
trash empty -y 2>/dev/null || true

# -----------------------------------------------------------------------
# Layer 1: PATH shim
# -----------------------------------------------------------------------
echo "test" > /tmp/trashd_it_shim.txt 2>/dev/null || true
# /tmp is in never_trash so use home
echo "shim_test" > /root/trashd_it_shim.txt
rm /root/trashd_it_shim.txt
if trash ls 2>&1 | grep -q "trashd_it_shim"; then
    pass "Layer 1: shim trashes file"
else
    fail "Layer 1: shim trashes file" "not found in trash"
fi
trash undo >/dev/null 2>&1
rm --permanent /root/trashd_it_shim.txt 2>/dev/null

# -----------------------------------------------------------------------
# Layer 2: LD_PRELOAD
# -----------------------------------------------------------------------
echo "preload_test" > /root/trashd_it_preload.txt
python3 -c "import os; os.remove('/root/trashd_it_preload.txt')" 2>/dev/null
if trash ls 2>&1 | grep -q "trashd_it_preload"; then
    pass "Layer 2: LD_PRELOAD trashes python unlink"
else
    fail "Layer 2: LD_PRELOAD trashes python unlink" "not found in trash"
fi
trash empty -y >/dev/null 2>&1

# -----------------------------------------------------------------------
# Bypass: --permanent
# -----------------------------------------------------------------------
echo "perm" > /root/trashd_it_perm.txt
rm --permanent /root/trashd_it_perm.txt
if trash ls 2>&1 | grep -q "trashd_it_perm"; then
    fail "Bypass: --permanent" "file found in trash (should not be)"
else
    pass "Bypass: --permanent"
fi

# -----------------------------------------------------------------------
# Bypass: TRASH_BYPASS=1
# -----------------------------------------------------------------------
echo "bypass" > /root/trashd_it_bypass.txt
TRASH_BYPASS=1 rm /root/trashd_it_bypass.txt
if trash ls 2>&1 | grep -q "trashd_it_bypass"; then
    fail "Bypass: TRASH_BYPASS=1" "file found in trash"
else
    pass "Bypass: TRASH_BYPASS=1"
fi

# -----------------------------------------------------------------------
# trash undo
# -----------------------------------------------------------------------
echo "undo_test" > /root/trashd_it_undo.txt
rm /root/trashd_it_undo.txt
trash undo >/dev/null 2>&1
if [ -f /root/trashd_it_undo.txt ]; then
    pass "trash undo restores file"
else
    fail "trash undo restores file" "file not restored"
fi
rm --permanent /root/trashd_it_undo.txt 2>/dev/null

# -----------------------------------------------------------------------
# trash restore with --to
# -----------------------------------------------------------------------
echo "restore_to" > /root/trashd_it_rto.txt
rm /root/trashd_it_rto.txt
trash restore trashd_it_rto.txt --to /root/trashd_it_rto_alt.txt >/dev/null 2>&1
if [ -f /root/trashd_it_rto_alt.txt ]; then
    pass "trash restore --to"
else
    fail "trash restore --to" "file not at alternate path"
fi
rm --permanent /root/trashd_it_rto_alt.txt 2>/dev/null

# -----------------------------------------------------------------------
# trash purge
# -----------------------------------------------------------------------
echo "purge_me" > /root/trashd_it_purge.txt
rm /root/trashd_it_purge.txt
trash purge trashd_it_purge.txt >/dev/null 2>&1
if trash ls 2>&1 | grep -q "trashd_it_purge"; then
    fail "trash purge" "entry still in trash"
else
    pass "trash purge"
fi

# -----------------------------------------------------------------------
# trash empty -y
# -----------------------------------------------------------------------
echo "e1" > /root/trashd_it_e1.txt
echo "e2" > /root/trashd_it_e2.txt
rm /root/trashd_it_e1.txt /root/trashd_it_e2.txt
trash empty -y >/dev/null 2>&1
if [ "$(trash ls 2>&1)" = "Trash is empty." ]; then
    pass "trash empty -y"
else
    fail "trash empty -y" "trash not empty after empty"
fi

# -----------------------------------------------------------------------
# .git/* pattern (infix glob)
# -----------------------------------------------------------------------
mkdir -p /root/trashd_it_repo/.git/objects
echo "obj" > /root/trashd_it_repo/.git/objects/test_obj
python3 -c "import os; os.remove('/root/trashd_it_repo/.git/objects/test_obj')" 2>/dev/null
if trash ls 2>&1 | grep -q "test_obj"; then
    fail ".git/* skip pattern" "git object was trashed"
else
    pass ".git/* skip pattern"
fi
rm -rf /root/trashd_it_repo 2>/dev/null

# -----------------------------------------------------------------------
# Restore conflict
# -----------------------------------------------------------------------
echo "v1" > /root/trashd_it_conflict.txt
rm /root/trashd_it_conflict.txt
echo "v2" > /root/trashd_it_conflict.txt
OUTPUT=$(trash restore trashd_it_conflict.txt 2>&1 || true)
if echo "$OUTPUT" | grep -qiE "already exists|conflict"; then
    pass "Restore conflict detection"
else
    fail "Restore conflict detection" "got: $OUTPUT"
fi
rm --permanent /root/trashd_it_conflict.txt 2>/dev/null
trash empty -y >/dev/null 2>&1

# -----------------------------------------------------------------------
# Duplicate filename unique IDs
# -----------------------------------------------------------------------
echo "first" > /root/trashd_it_dup.txt
rm /root/trashd_it_dup.txt
echo "second" > /root/trashd_it_dup.txt
rm /root/trashd_it_dup.txt
COUNT=$(trash ls 2>&1 | grep -c "trashd_it_dup")
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
if trash fsck 2>&1 | grep -q "orphan"; then
    pass "trash fsck detects orphans"
else
    fail "trash fsck detects orphans" "orphan not detected"
fi
rm -f ~/.local/share/Trash/files/trashd_it_orphan

# -----------------------------------------------------------------------
# trash restore --force (auto-rename on conflict)
# -----------------------------------------------------------------------
echo "force_test" > /root/trashd_it_force.txt
rm /root/trashd_it_force.txt
echo "blocker" > /root/trashd_it_force.txt
trash restore trashd_it_force.txt --force >/dev/null 2>&1
if [ -f /root/trashd_it_force.txt.1 ]; then
    pass "trash restore --force auto-renames"
else
    fail "trash restore --force auto-renames" "renamed file not found"
fi
rm --permanent /root/trashd_it_force.txt /root/trashd_it_force.txt.1 2>/dev/null
trash empty -y >/dev/null 2>&1

# -----------------------------------------------------------------------
# trash restore --all (batch restore)
# -----------------------------------------------------------------------
echo "batch1" > /root/trashd_it_b1.py
echo "batch2" > /root/trashd_it_b2.py
rm /root/trashd_it_b1.py /root/trashd_it_b2.py
OUTPUT=$(trash restore '*.py' --all 2>&1 || true)
if echo "$OUTPUT" | grep -q "Restored:" && [ -f /root/trashd_it_b1.py ] && [ -f /root/trashd_it_b2.py ]; then
    pass "trash restore --all batch restore"
else
    fail "trash restore --all batch restore" "files not restored"
fi
rm --permanent /root/trashd_it_b1.py /root/trashd_it_b2.py 2>/dev/null
trash empty -y >/dev/null 2>&1

# -----------------------------------------------------------------------
# trash ls --after time filter
# -----------------------------------------------------------------------
echo "recent" > /root/trashd_it_recent.txt
rm /root/trashd_it_recent.txt
if trash ls --after 1h 2>&1 | grep -q "trashd_it_recent"; then
    pass "trash ls --after shows recent items"
else
    fail "trash ls --after shows recent items" "recent file not shown"
fi
trash empty -y >/dev/null 2>&1

# -----------------------------------------------------------------------
# trash ls --json
# -----------------------------------------------------------------------
echo "jsontest" > /root/trashd_it_json.txt
rm /root/trashd_it_json.txt
if trash ls --json 2>&1 | grep -q '"id"'; then
    pass "trash ls --json outputs JSON"
else
    fail "trash ls --json outputs JSON" "no JSON output"
fi
trash empty -y >/dev/null 2>&1

# -----------------------------------------------------------------------
# trash config show
# -----------------------------------------------------------------------
if trash config show 2>&1 | grep -q "never_trash"; then
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
echo "compress_test_data_repeated" > /root/trashd_it_comp.txt
for i in $(seq 1 100); do echo "line $i of repeated data for compression test" >> /root/trashd_it_comp.txt; done
rm /root/trashd_it_comp.txt
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
echo "secret" > /root/trashd_it_perms.txt
chmod 600 /root/trashd_it_perms.txt
rm /root/trashd_it_perms.txt
trash undo >/dev/null 2>&1
PERMS=$(stat -c %a /root/trashd_it_perms.txt 2>/dev/null)
if [ "$PERMS" = "600" ]; then
    pass "Permissions preserved on restore"
else
    fail "Permissions preserved on restore" "got $PERMS, expected 600"
fi
rm --permanent /root/trashd_it_perms.txt 2>/dev/null
trash empty -y >/dev/null 2>&1

# -----------------------------------------------------------------------
# trash self-update --check
# -----------------------------------------------------------------------
if trash self-update --check 2>&1 | grep -qE "Up to date|Update available"; then
    pass "trash self-update --check"
else
    fail "trash self-update --check" "unexpected output"
fi

# -----------------------------------------------------------------------
# Local .trashd.toml override
# -----------------------------------------------------------------------
mkdir -p /root/trashd_it_local
echo 'only_trash = ["*.keep"]' > /root/trashd_it_local/.trashd.toml
echo "should trash" > /root/trashd_it_local/test.keep
echo "should skip" > /root/trashd_it_local/test.skip
python3 -c "import os; os.remove('/root/trashd_it_local/test.keep')" 2>/dev/null
python3 -c "import os; os.remove('/root/trashd_it_local/test.skip')" 2>/dev/null
KEEP_TRASHED=$(trash ls 2>&1 | grep -c "test.keep" || true)
SKIP_TRASHED=$(trash ls 2>&1 | grep -c "test.skip" || true)
if [ "$KEEP_TRASHED" -ge 1 ] && [ "$SKIP_TRASHED" -eq 0 ]; then
    pass "Local .trashd.toml only_trash override"
else
    fail "Local .trashd.toml only_trash override" "keep=$KEEP_TRASHED skip=$SKIP_TRASHED"
fi
rm -rf /root/trashd_it_local 2>/dev/null
trash empty -y >/dev/null 2>&1

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
echo "  $PASS passed, $FAIL failed"
echo "========================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
