/*
 * Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "dev.h"
#include "input.h"
#include "util.h"

/*
 * We believe that there's a limit of 32 /dev/input/eventX devices in the
 * kernel. It's not quite clear. Anyway, we should probably never have more than
 * that in practice on Chrome OS anyway, so our algorithm is to check for the
 * first 32 nodes explicitly, then keep checking for any further ones until we
 * find an entry missing. (This is way simpler than using actual POSIX globbing
 * or directory entry APIs.)
 */
#define EVDEV_MAX 32

int dev_init(void)
{
	char path[64];
	int i;

	for (i = 0;; i++) {
		snprintf(path, sizeof(path), "/dev/input/event%d", i);
		if (access(path, F_OK)) {
			if (i >= EVDEV_MAX)
				break;
			else
				continue;
		}
		input_add(path);
	}

	return 0;
}

void dev_close(void)
{
}

void dev_add_fds(fd_set* read_set, fd_set* exception_set, int *maxfd)
{
}

void dev_dispatch_io(fd_set* read_set, fd_set* exception_set)
{
}
