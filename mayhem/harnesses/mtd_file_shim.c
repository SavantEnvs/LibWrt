/*
 * Environment mock for fritz_tffs_nand_read: lets the tool read a regular file as if it
 * were a NAND MTD device (linked with -Wl,--wrap=ioctl; only the two MTD ioctls the tool
 * issues are emulated, everything else goes to the real ioctl()).
 *
 * File layout (the fuzz input):  N data sectors of 0x800 bytes, followed by N OOB areas
 * of 0x40 bytes (one per sector), N = file_size / (0x800 + 0x40).
 *   MEMGETINFO -> size = N * 0x800, erasesize = 4 sectors (8 KiB), writesize = 0x800,
 *                 oobsize = 0x40
 *   MEMREADOOB -> copies the OOB area of the sector at oob.start
 * Data-sector reads go through the tool's own pread() on the file, unchanged.
 */
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <mtd/mtd-user.h>

#define SECTOR 0x800u
#define OOB 0x40u
#define ERASE_SECTORS 4u

int __real_ioctl(int fd, unsigned long req, ...);

static uint64_t nsectors(int fd)
{
	struct stat st;
	if (fstat(fd, &st) < 0 || st.st_size < 0)
		return 0;
	return (uint64_t)st.st_size / (SECTOR + OOB);
}

int __wrap_ioctl(int fd, unsigned long req, ...)
{
	va_list ap;
	void *arg;

	va_start(ap, req);
	arg = va_arg(ap, void *);
	va_end(ap);

	if (req == MEMGETINFO) {
		struct mtd_info_user *info = arg;
		memset(info, 0, sizeof(*info));
		info->type = MTD_NANDFLASH;
		info->size = (uint32_t)(nsectors(fd) * SECTOR);
		info->erasesize = ERASE_SECTORS * SECTOR;
		info->writesize = SECTOR;
		info->oobsize = OOB;
		return 0;
	}
	if (req == MEMREADOOB) {
		struct mtd_oob_buf *oob = arg;
		uint64_t n = nsectors(fd);
		uint64_t sec = oob->start / SECTOR;
		uint32_t len = oob->length > OOB ? OOB : oob->length;
		if (sec >= n)
			return -1;
		if (pread(fd, oob->ptr, len, (off_t)(n * SECTOR + sec * OOB)) != (ssize_t)len)
			return -1;
		return 0;
	}
	return __real_ioctl(fd, req, arg);
}
