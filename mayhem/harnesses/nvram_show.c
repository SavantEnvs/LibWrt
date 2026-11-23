/*
 * Test-only driver for mayhem/test.sh (built with normal flags): opens an NVRAM partition image
 * with the library's public API, like `nvram show` (cli.c), and prints every name=value pair,
 * sorted, followed by the header nvram_commit() regenerates (len, crc8). argv[2] is the
 * partition size (the MTD erasesize nvram_find_mtd() would read from /proc/mtd).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nvram.h"

extern size_t nvram_part_size;

static int cmp(const void *a, const void *b) { return strcmp(*(char **)a, *(char **)b); }

int main(int argc, char **argv)
{
	nvram_handle_t *h;
	nvram_tuple_t *t, *next;
	char *lines[1024];
	int n = 0, i;

	if (argc != 3)
		return 2;
	nvram_part_size = strtoul(argv[2], NULL, 0);
	if (!(h = nvram_open(argv[1], NVRAM_RO))) {
		fprintf(stderr, "nvram_open failed\n");
		return 1;
	}
	for (t = nvram_getall(h); t; t = next) {
		next = t->next;
		if (n < 1024 && asprintf(&lines[n], "%s=%s", t->name, t->value) > 0)
			n++;
		free(t);
	}
	qsort(lines, n, sizeof(*lines), cmp);
	for (i = 0; i < n; i++) {
		puts(lines[i]);
		free(lines[i]);
	}
	nvram_commit(h);
	printf("len=%u crc=0x%02x\n", nvram_header(h)->len, nvram_header(h)->crc_ver_init & 0xff);
	nvram_close(h);
	return 0;
}
