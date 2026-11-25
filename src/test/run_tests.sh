#!/bin/sh
# Run the self checking test_storage scripts.
# Usage: run_tests.sh [path to test_storage] [log directory]
# Logs go to the log directory, a new temporary directory by default.
TEST_STORAGE=${1:-./test_storage}
LOGDIR=${2:-$(mktemp -d "${TMPDIR:-/tmp}/dawn-tests.XXXXXX")}
DIR=$(dirname "$0")
fail=0

mkdir -p "$LOGDIR" || exit 1

for s in ieee80211_freq kick_absolute_rssi; do
	log="$LOGDIR/$s.log"
	if "$TEST_STORAGE" -q --script "$DIR/$s.script" > "$log" 2>&1 && ! grep -q "FAIL" "$log"; then
		echo "PASS $s ($(grep -c PASS "$log") checks)"
	else
		echo "FAIL $s, see $log"
		grep "FAIL" "$log"
		fail=1
	fi
done

echo "Logs in $LOGDIR"
exit $fail
