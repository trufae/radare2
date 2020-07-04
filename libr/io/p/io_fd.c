/* radare - LGPL - Copyright 2020 - pancake */

#include "r_io.h"
#include "r_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <r_cons.h>
#include <sys/types.h>

#define FDURI "fd://"

typedef struct {
	int fd;
} RIOFdata;

static int __write(RIO *io, RIODesc *desc, const ut8 *buf, int count) {
	RIOFdata *mal = (RIOFdata*)desc->data;
	if (mal) {
		return write (mal->fd, buf, count);
	}
	return -1;
}

static bool __resize(RIO *io, RIODesc *desc, ut64 count) {
	RIOFdata *mal = (RIOFdata*)desc->data;
	if (mal) {
		return ftruncate (mal->fd, count) == 0;
	}
	return false;
}

static int __read(RIO *io, RIODesc *desc, ut8 *buf, int count) {
	RIOFdata *mal = (RIOFdata*)desc->data;
	if (mal) {
		r_cons_break_push (NULL, NULL);
		int res = read (mal->fd, buf, count);
		r_cons_break_pop ();
		return res;
	}
	return -1;
}

static int __close(RIODesc *desc) {
	R_FREE (desc->data);
	return 0;
}

static ut64 __lseek(RIO* io, RIODesc *desc, ut64 offset, int whence) {
	RIOFdata *mal = (RIOFdata*)desc->data;
	if (mal) {
		return lseek (mal->fd, offset, whence);
	}
	return 0;
}

static bool __check(RIO *io, const char *pathname, bool many) {
	return !strncmp (pathname, FDURI, strlen (FDURI));
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (__check (io, pathname, 0)) {
		if (r_sandbox_enable (false)) {
			eprintf ("Do not permit " FDURI " in sandbox mode.\n");
			return NULL;
		}
		RIOFdata *mal = R_NEW0 (RIOFdata);
		if (mal) {
			mal->fd = r_num_math (NULL, pathname + 5);
			if (((int)mal->fd) < 0) {
				free (mal);
				eprintf ("Invalid filedescriptor.\n");
				return NULL;
			}
		}
		return r_io_desc_new (io, &r_io_plugin_fd, pathname, R_PERM_RW | rw, mode, mal);
	}
	return NULL;
}

RIOPlugin r_io_plugin_fd = {
	.name = "fd",
	.desc = "Local process filedescriptor IO",
	.uris = FDURI,
	.license = "LGPL3",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __check,
	.lseek = __lseek,
	.write = __write,
	.resize = __resize,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_fd,
	.version = R2_VERSION
};
#endif
