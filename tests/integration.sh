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
