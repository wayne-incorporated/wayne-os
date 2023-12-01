/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crosid.h"

static const char *sysroot = "";

void crosid_set_sysroot(const char *path)
{
	sysroot = path;
}

/*
 * Get the file size via seeking and rewinding.  Note that this needs
 * to be done via a seek instead of a stat, since some files in /proc
 * and /sys have a size of zero when stat'ed.
 */
static ssize_t get_file_size(FILE *f)
{
	ssize_t size;

	if (fseek(f, 0, SEEK_END) < 0)
		return -1;

	size = ftell(f);
	rewind(f);
	return size;
}

int crosid_read_file(const char *dir, const char *file, char **data_ptr,
		     size_t *size_ptr)
{
	FILE *f;
	char *buf = NULL;
	ssize_t seek_size;
	ssize_t size;
	char full_path[PATH_MAX] = { 0 };
	/*
	 * Using an int avoids compiler warning
	 * (comparison of integers of different signs)
	 */
	int full_path_sz = sizeof(full_path) - 1;

	if (snprintf(full_path, full_path_sz, "%s%s/%s", sysroot, dir, file) >=
	    full_path_sz) {
		crosid_log(LOG_ERR, "File path too long!\n");
		crosid_log(LOG_ERR, "  sysroot=%s\n", sysroot);
		crosid_log(LOG_ERR, "  dir=%s\n", dir);
		crosid_log(LOG_ERR, "  file=%s\n", file);
		return -1;
	}

	*data_ptr = NULL;
	f = fopen(full_path, "rb");
	if (!f) {
		/* This one is SPEW, as we expect some files to not exist */
		crosid_log(LOG_SPEW, "Failed to open \"%s\" for reading: %s\n",
			   full_path, strerror(errno));
		return -1;
	}

	seek_size = get_file_size(f);
	if (seek_size < 0) {
		crosid_log(LOG_ERR,
			   "Failed to get file size while reading \"%s\": %s\n",
			   full_path, strerror(errno));
		goto err;
	}

	buf = malloc(seek_size + 1);
	if (!buf) {
		crosid_log(LOG_ERR,
			   "Failed to allocate %zu bytes while reading %s\n",
			   seek_size + 1, full_path);
		goto err;
	}

	/*
	 * 0 <= fread() <= size
	 * Normally we'd expect the return value to be the size, but
	 * in SMBIOS sysfs, the kernel lets us seek further than we
	 * can read, thus, we have to handle getting a value less than
	 * the size we got thru seek.
	 */
	size = fread(buf, 1, seek_size, f);
	if (size != seek_size && !feof(f)) {
		crosid_log(LOG_ERR, "%s was not at EOF after reading\n",
			   full_path);
		goto err;
	}

	buf[size] = '\0';
	fclose(f);

	*data_ptr = buf;
	if (size_ptr)
		*size_ptr = size;
	return 0;

err:
	fclose(f);
	free(buf);
	return -1;
}
