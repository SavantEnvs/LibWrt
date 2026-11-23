/*
 * libFuzzer harness for the BCM4908 image parser and its bootfs (JFFS2) walker
 * (package/utils/bcm4908img).
 *
 * bcm4908img_parse() checks a CRC32 over the whole firmware area against the tail
 * before anything else runs, so a mutated image almost never gets past it through the
 * CLI targets (bcm4908img-info / bcm4908img-bootfs-ls; those still fuzz the check itself).
 * This harness does what the tool does after it edits an image (bcm4908img_bootfs_mv:
 * bcm4908img_calc_crc32() + rewrite tail->crc32): it recomputes the CRC over the same
 * range the parser hashes and stores it in the tail. Only the checksum is updated; the
 * header, offset search, padding/rootfs scan and JFFS2 nodes are parsed exactly as given.
 *
 * The parser and the walker are static, so the tool's translation unit is included here
 * (build.sh renames its main with -Dmain=bcm4908img_main). bcm4908img_parse() calls
 * fstat(fileno(fp)), which an fmemopen() stream can't answer, so the input goes into a
 * memfd that is truncated and rewritten for each input (no state survives an input).
 */
#define _GNU_SOURCE
#include "bcm4908img.c"

#include <stdint.h>
#include <sys/mman.h>

static int mfd = -1;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	mfd = memfd_create("bcm4908img", 0);
	if (mfd < 0)
		abort();
	return 0;
}

/* The range bcm4908img_parse() hashes: [cferom_offset, tail_offset), same rules. */
static void fix_crc(uint8_t *img, size_t size)
{
	struct chk_header chk;
	struct linksys_tail linksys;
	size_t cferom = 0, tail = size - sizeof(struct bcm4908img_tail);
	uint32_t crc;

	memcpy(&chk, img, sizeof(chk));
	if (be32_to_cpu(chk.magic) == 0x2a23245e)
		cferom = be32_to_cpu(chk.header_len);
	memcpy(&linksys, img + size - sizeof(linksys), sizeof(linksys));
	if (!memcmp(linksys.magic, ".LINKSYS.", sizeof(linksys.magic)))
		tail -= sizeof(linksys);
	if (cferom >= tail)
		return; /* parse rejects it before the CRC ("Failed to find bootfs offset") */

	crc = cpu_to_le32(bcm4908img_crc32(0xffffffff, img + cferom, tail - cferom));
	memcpy(img + tail + offsetof(struct bcm4908img_tail, crc32), &crc, sizeof(crc));
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct bcm4908img_info info;
	uint8_t *img;
	FILE *fp;
	int fd;

	/* bcm4908img_parse() needs a 1024-byte header and a 1024-byte trailer block */
	if (size < 1024)
		return -1;

	img = malloc(size);
	memcpy(img, data, size);
	fix_crc(img, size);

	if (ftruncate(mfd, 0) || pwrite(mfd, img, size, 0) != (ssize_t)size)
		abort();
	free(img);

	fd = dup(mfd);
	fp = fdopen(fd, "r");
	if (!fp)
		abort();
	if (!bcm4908img_parse(fp, &info)) {
		/* what `bcm4908img info` prints, then `bcm4908img bootfs ls` */
		printf("bootfs 0x%zx padding 0x%zx rootfs 0x%zx crc 0x%08x\n", info.bootfs_offset,
		       info.padding_offset, info.rootfs_offset, info.crc32);
		bcm4908img_bootfs_ls(fp, &info);
	}
	fclose(fp);
	return 0;
}
