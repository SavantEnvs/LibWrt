#!/usr/bin/env bash
#
# mayhem/test.sh — known-answer tests for the LibWrt tools (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Known-answer tests: the LibWrt tools (built by build.sh with NORMAL flags into mayhem/out/test)
# are run on the committed fixtures in mayhem/testdata/ (made by mayhem/gen_seeds.py) and their
# output is compared with the exact expected text.
T="$SRC/mayhem/out/test"
D="$SRC/mayhem/testdata"
for b in fritz_tffs_read fritz_tffs_nand_read bcm4908img osafeloader conf nvram_show; do
  [ -x "$T/$b" ] || { echo "missing $T/$b — run mayhem/build.sh first" >&2; emit_ctrf "libwrt-tools-kat" 0 1; exit 1; }
done
WORK="$(mktemp -d "${TMPDIR:-/tmp}/libwrt-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

passed=0 failed=0
# check <name> <expected stdout> <command...>
check() {
  local name="$1" expected="$2"; shift 2
  local got
  got="$(cd "$WORK" && "$@" 2>/dev/null)"
  if [ "$got" == "$expected" ]; then
    passed=$((passed + 1)); echo "PASS $name"
  else
    failed=$((failed + 1)); echo "FAIL $name"; echo "  expected: $(printf %q "$expected")"; echo "  got:      $(printf %q "$got")"
  fi
}

check tffs_read_all   $'macaddr=00:11:22:33:44:55\nserial=ABCD' "$T/fritz_tffs_read" -i "$D/nor.tffs" -a
check tffs_read_list  $'macaddr\nserial'                       "$T/fritz_tffs_read" -i "$D/nor.tffs" -l
check tffs_read_name  'ABCD'                                    "$T/fritz_tffs_read" -i "$D/nor.tffs" -n serial
check tffs_nand_all   $'macaddr=00:11:22:33:44:55\nserial=ABCD' "$T/fritz_tffs_nand_read" -d "$D/nand.tffs" -a
check tffs_nand_name  '00:11:22:33:44:55'                       "$T/fritz_tffs_nand_read" -d "$D/nand.tffs" -n macaddr
check bcm4908img_info $'bootfs offset:\t0x0\nrootfs offset:\t0x20000\nChecksum:\t0xb1559014' \
                                                                "$T/bcm4908img" info -i "$D/bcm4908.bin"
check bcm4908img_bootfs_ls $'cferam.000\nvmlinux.lz\n94908.dtb' "$T/bcm4908img" bootfs -i "$D/bcm4908.bin" ls
check osafeloader_info "$(printf '%10s: %s\n%10s: %s\n%10s: %s\n%10s: %s\n%10s: %s' \
    'Image size' 0 MD5 91dcd7fd5a66ad287af7fd8601c12dbb \
    Partition 'partition-table (0x800 - 0x1000)' Partition 'os-image (0x1000 - 0x114b45)' \
    Partition 'file-system (0x114b45 - 0x2e4b49)')"              "$T/osafeloader" info "$D/safeloader.bin"
check kconfig_alldefconfig "$(cat "$D/Kconfig.config.expected")" env -u ARCH -u KCONFIG_CONFIG bash -c '"$1" --alldefconfig "$2" >/dev/null && cat .config' _ "$T/conf" "$D/Kconfig"

# nvram_open() maps the partition read-write (O_RDWR), so the fixture is copied into the scratch dir.
check nvram_show_commit $'boardtype=0x0472\net0macaddr=00:11:22:33:44:55\nlan_ipaddr=192.168.1.1\nsdram_config=0x8040\nsdram_init=0x0419\nsdram_ncdl=0x00000000\nsdram_refresh=0x0000\nlen=172 crc=0xa9' \
    bash -c 'cp "$2" nvram.bin && "$1" nvram.bin 0x10000' _ "$T/nvram_show" "$D/nvram.bin"

emit_ctrf "libwrt-tools-kat" "$passed" "$failed" 0
