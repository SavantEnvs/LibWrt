/*
 * libFuzzer harness for the Broadcom NVRAM partition parser (package/utils/nvram/src/nvram.c),
 * through its public API (nvram.h), the way the `nvram` CLI (cli.c) drives it:
 *   nvram_open(file, NVRAM_RO)  - magic scan + header check + "name=value\0...\0\0" rehash
 *   nvram_getall / nvram_get     - `nvram show` / `nvram get`
 *   nvram_set / nvram_unset / nvram_commit - `nvram set|unset|commit` (regenerates header, CRC8)
 *
 * The input is the content of the NVRAM MTD partition. On a device nvram_find_mtd() reads the
 * partition size (the MTD erasesize) from /proc/mtd into the global nvram_part_size, and
 * nvram_open() maps exactly that many bytes of the partition. The harness fixes the size at
 * 64 KiB (the common Broadcom value), writes the input to a scratch file and extends it to the
 * partition size (the tail reads as zeros, like a short image). An input longer than the
 * partition cannot be a partition image and is rejected with -1.
 *
 * The RO handle uses a MAP_PRIVATE mapping, so nvram_commit() rewrites only private memory; the
 * scratch file is unlinked after every input, so nothing carries over between inputs.
 * mmap() is wrapped only to drop MAP_LOCKED (the fuzzing sandbox's RLIMIT_MEMLOCK can be below
 * one partition); the mapping is otherwise the library's own.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "nvram.h"

extern size_t nvram_part_size;

#define PART_SIZE 0x10000

void *__real_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off);
void *__wrap_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off)
{
	return __real_mmap(addr, len, prot, flags & ~MAP_LOCKED, fd, off);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char path[4096];
	const char *tmp = getenv("TMPDIR");
	nvram_handle_t *h;
	nvram_tuple_t *t, *next;
	int fd;

	if (size > PART_SIZE)
		return -1;

	snprintf(path, sizeof(path), "%s/nvram-fuzz-XXXXXX", tmp && *tmp ? tmp : "/tmp");
	fd = mkstemp(path);
	if (fd < 0)
		return 0;
	if (write(fd, data, size) != (ssize_t)size || ftruncate(fd, PART_SIZE) != 0) {
		close(fd);
		unlink(path);
		return 0;
	}
	close(fd);

	nvram_part_size = PART_SIZE;
	h = nvram_open(path, NVRAM_RO);
	if (h) {
		size_t n = 0;

		for (t = nvram_getall(h); t; t = next) {   /* `nvram show` */
			next = t->next;
			n += strlen(t->name) + strlen(t->value);
			free(t);
		}
		(void)nvram_get(h, "sdram_init");          /* `nvram get` */
		(void)nvram_get(h, "lan_ipaddr");
		nvram_set(h, "fuzz", "1");                 /* `nvram set/unset/commit` */
		nvram_unset(h, "lan_ipaddr");
		nvram_commit(h);
		(void)n;
		nvram_close(h);
	}
	unlink(path);
	return 0;
}
