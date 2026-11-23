#!/usr/bin/env bash
#
# mayhem/build.sh — LibWrt (OpenWrt fork) fuzz targets.
#
# The OpenWrt buildroot downloads its toolchain and every package at build time, so it is NOT
# run here. The in-tree C that parses untrusted bytes is a set of small standalone tools; each
# is compiled directly from its upstream source with the sanitizers:
#   ead-handle-packet     libFuzzer, ead daemon packet handler (package/network/services/ead)
#   nvram-open            libFuzzer, Broadcom NVRAM partition parser via nvram.h (package/utils/nvram)
#   bcm4908img-parse      libFuzzer, bcm4908img_parse + bootfs ls, image CRC32 recomputed per input
#   bcm4908img-info       AFL file-input, `bcm4908img info -i @@`        (package/utils/bcm4908img)
#   bcm4908img-bootfs-ls  AFL file-input, `bcm4908img bootfs -i @@ ls`
#   fritz-tffs-read       AFL file-input, `fritz_tffs_read -i @@ -a`     (package/utils/fritz-tools)
#   fritz-tffs-nand-read  AFL file-input, `fritz_tffs_nand_read -d @@ -a -o` (MTD ioctls mocked)
#   fritz-cal-extract     AFL file-input, `fritz_cal_extract -e 0x207 @@`
#   osafeloader-info      AFL file-input, `osafeloader info @@`          (package/utils/osafeloader)
#   osafeloader-extract   AFL file-input, `osafeloader extract @@ -p os-image -o /dev/null`
#   jboot-config-read     AFL file-input, `jboot_config_read -i @@ -m`   (package/utils/jboot-tools)
# The CLIs exit() on bad input, so they are file-input (AFL-instrumented) targets rather than
# in-process harnesses. Everything lands in mayhem/out/ (gitignored).
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${AFL_CC:=afl-clang-fast}"
export AFL_QUIET=1

cd "$SRC"
OUT="$SRC/mayhem/out"
OBJ="$OUT/obj"
TST="$OUT/test"
mkdir -p "$OUT" "$OBJ" "$TST"

FFLAGS="-O1 $SANITIZER_FLAGS $DEBUG_FLAGS"
U=package/utils
EAD=package/network/services/ead/src

# lsan_off: linked into every sanitized binary (SPEC §6.2 item 15).
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$OBJ/lsan_off.o"
$AFL_CC $SANITIZER_FLAGS $DEBUG_FLAGS -x c++ -c mayhem/lsan_off.cc -o "$OBJ/lsan_off_afl.o"

# ---- 1) ead: tinysrp + ead-crypt + the daemon TU, sanitized, linked into the harness -------
# libFuzzer coverage instrumentation for the daemon code (not only the harness)
EADF="$FFLAGS -fsanitize=fuzzer-no-link"
EADINC="-I$SRC/mayhem/harnesses/tinysrp -I$SRC/$EAD -I$SRC/$EAD/tinysrp"
ead_objs=()
# (tinysrp.c, t_client.c, t_getpass.c: client side and terminal prompt, not used by the daemon)
for s in t_getconf t_conv t_sha t_math t_misc t_pw t_read t_server \
         t_truerand bn_add bn_ctx bn_div bn_exp bn_mul bn_word bn_asm bn_lib bn_shift bn_sqr; do
  $CC $EADF -fcommon -w -Wno-error=implicit-function-declaration -Wno-error=implicit-int -include stdlib.h -include string.h -include strings.h $EADINC -c "$EAD/tinysrp/$s.c" -o "$OBJ/srp_$s.o"
  ead_objs+=("$OBJ/srp_$s.o")
done
for s in ead-crypt libbridge_init; do
  $CC $EADF -fcommon -w -include arpa/inet.h $EADINC -c "$EAD/$s.c" -o "$OBJ/ead_$s.o"
  ead_objs+=("$OBJ/ead_$s.o")
done
# The SRP handshake (GET_PRIME/SEND_A/SEND_AUTH) is unreachable for any input: once a frame names a
# user with a `$1$` passwd entry, prepare_password() strncpy()s into `static const char password[]`
# (ead.c:218, write to a const object -> SEGV in .rodata), and with that object writable it then
# memcmp()s 32 bytes of the 20-byte stack array `dig` (ead.c:231, stack-buffer-overflow). Both are
# upstream bugs on every login, so the harness covers the pre-auth framing/state machine up to there.
$CC $EADF -fcommon -w -include arpa/inet.h -include sys/wait.h $EADINC -Dmain=ead_main -c mayhem/harnesses/ead_fuzz.c -o "$OBJ/ead_fuzz.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OBJ/ead_fuzz.o" "${ead_objs[@]}" \
  "$OBJ/lsan_off.o" -lpcap -o "$OUT/ead-handle-packet"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OBJ/standalone_main.o" "$OBJ/ead_fuzz.o" "${ead_objs[@]}" \
  "$OBJ/lsan_off.o" -lpcap -o "$OUT/ead-handle-packet-standalone"

# ---- 1b) nvram: libnvram (nvram.c, crc.c) sanitized + SanCov, public-API harness ----------------
NV=package/utils/nvram/src
nv_objs=()
for s in nvram crc; do
  $CC $FFLAGS -fsanitize=fuzzer-no-link -w -I"$NV" -c "$NV/$s.c" -o "$OBJ/nvram_$s.o"
  nv_objs+=("$OBJ/nvram_$s.o")
done
$CC $FFLAGS -fsanitize=fuzzer-no-link -I"$NV" -c mayhem/harnesses/nvram_fuzz.c -o "$OBJ/nvram_fuzz.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OBJ/nvram_fuzz.o" "${nv_objs[@]}" \
  "$OBJ/lsan_off.o" -Wl,--wrap=mmap -o "$OUT/nvram-open"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OBJ/standalone_main.o" "$OBJ/nvram_fuzz.o" "${nv_objs[@]}" \
  "$OBJ/lsan_off.o" -Wl,--wrap=mmap -o "$OUT/nvram-open-standalone"

# ---- 1c) bcm4908img: parser + bootfs walker in-process, image CRC fixed up per input ----------
BCM=package/utils/bcm4908img/src
$CC $FFLAGS -fsanitize=fuzzer-no-link -w -I"$BCM" -Dmain=bcm4908img_main \
  -c mayhem/harnesses/bcm4908img_fuzz.c -o "$OBJ/bcm4908img_fuzz.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OBJ/bcm4908img_fuzz.o" "$OBJ/lsan_off.o" \
  -o "$OUT/bcm4908img-parse"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OBJ/standalone_main.o" "$OBJ/bcm4908img_fuzz.o" "$OBJ/lsan_off.o" \
  -o "$OUT/bcm4908img-parse-standalone"

# ---- 2) image/partition parsers: AFL-instrumented file-input CLIs ----------------------------
afl() { # afl <out> <sources/flags...>
  local o="$1"; shift
  $AFL_CC $FFLAGS -w "$@" "$OBJ/lsan_off_afl.o" -lstdc++ -o "$OUT/$o"
}
afl bcm4908img           "$U/bcm4908img/src/bcm4908img.c"
afl fritz_tffs_read      "$U/fritz-tools/src/fritz_tffs_read.c"
afl fritz_tffs_nand_read "$U/fritz-tools/src/fritz_tffs_nand_read.c" mayhem/harnesses/mtd_file_shim.c \
                         -Wl,--wrap=ioctl -fno-sanitize=alignment
afl fritz_cal_extract    "$U/fritz-tools/src/fritz_cal_extract.c" mayhem/harnesses/errno_reset.c -Wl,--wrap=getopt -lz
afl osafeloader          "$U/osafeloader/src/osafeloader.c" "$U/osafeloader/src/md5.c"
afl jboot_config_read    "$U/jboot-tools/src/jboot_config_read.c"
# Kconfig `conf` (lexer/parser shipped pre-generated): built only for the functional oracle below; it
# parses the build tree's own Config.in files (trusted input), so it is not a fuzz target.
KC=scripts/config
KCSRC="$KC/conf.c $KC/confdata.c $KC/expr.c $KC/lexer.lex.c $KC/menu.c $KC/parser.tab.c $KC/preprocess.c $KC/symbol.c $KC/util.c"

# ---- 3) functional-test builds: the same tools with NORMAL flags (no sanitizers) -------------
tcc() { local o="$1"; shift; $CC -O2 -w $COVERAGE_FLAGS "$@" -o "$TST/$o"; }
tcc fritz_tffs_read      "$U/fritz-tools/src/fritz_tffs_read.c"
tcc fritz_tffs_nand_read "$U/fritz-tools/src/fritz_tffs_nand_read.c" mayhem/harnesses/mtd_file_shim.c \
                         -Wl,--wrap=ioctl
tcc bcm4908img           "$U/bcm4908img/src/bcm4908img.c"
tcc osafeloader          "$U/osafeloader/src/osafeloader.c" "$U/osafeloader/src/md5.c"
tcc nvram_show         mayhem/harnesses/nvram_show.c "$NV/nvram.c" "$NV/crc.c" -I"$NV"
tcc conf                 $KCSRC -I"$KC" mayhem/harnesses/no_popen.c -Wl,--wrap=popen

echo "built: $(ls "$OUT" | tr '\n' ' ')"
