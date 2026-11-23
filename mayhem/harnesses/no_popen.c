/*
 * Environment mock for the Kconfig `conf` target (linked with -Wl,--wrap=popen): Kconfig's
 * $(shell,<cmd>) macro runs <cmd> through popen(). The fuzz input is the Kconfig text, so the
 * fuzzer must not be able to execute commands; popen() fails as if no shell were available,
 * which preprocess.c already handles (it reports the error and exits).
 */
#include <errno.h>
#include <stdio.h>
FILE *__wrap_popen(const char *command, const char *type)
{
	(void)command; (void)type;
	errno = ENOSYS;
	return NULL;
}
