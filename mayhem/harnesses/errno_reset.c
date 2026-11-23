/*
 * Environment fix for fritz_cal_extract (linked with -Wl,--wrap=getopt): its option parser tests
 * `errno` after strtoul() without clearing it first, so an errno left over from process start-up
 * (the AFL runtime's forkserver probe leaves EBADF) makes every option "fail to parse". Clearing
 * errno before each getopt() call gives the tool the errno a plain exec would give it.
 */
#include <errno.h>
int __real_getopt(int argc, char *const argv[], const char *optstring);
int __wrap_getopt(int argc, char *const argv[], const char *optstring)
{
	errno = 0;
	return __real_getopt(argc, argv, optstring);
}
