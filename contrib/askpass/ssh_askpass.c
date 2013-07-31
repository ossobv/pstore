#define _GNU_SOURCE
#include <sys/types.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>

static void init(void) __attribute__((constructor));

int (*real_open)(__const char *name, int flags, mode_t mode);

static void init(void) {
	real_open = dlsym(RTLD_NEXT, "open");
}

int open(const char *pathname, int flags, mode_t mode) {
	/*
	 * We need to return fail here because otherwise ssh won't use
	 * the SSH_ASKPASS envvar.
	 */
	if (strcmp(pathname, "/dev/tty") == 0) {
		errno = EACCES;
		return -1;
	}
	return real_open(pathname, flags, mode);
}
