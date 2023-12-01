/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crosid.h"

static int get_full_frid(char **frid_out)
{
	const static struct {
		const char *dir;
		const char *file;
	} files_to_try[] = {
		{ SYSFS_CHROMEOS_ACPI_PATH, "FRID" },
		{ PROC_FDT_CHROMEOS_PATH, "readonly-firmware-version" },
	};
	int rv;

	for (size_t i = 0; i < ARRAY_SIZE(files_to_try); i++) {
		rv = crosid_read_file(files_to_try[i].dir, files_to_try[i].file,
				      frid_out, NULL);

		if (rv >= 0)
			return rv;
	}

	return -1;
}

int crosid_probe_frid(struct crosid_optional_string *out)
{
	char *frid;
	size_t len;

	if (get_full_frid(&frid) < 0) {
		out->present = false;
		out->value = NULL;
		out->len = 0;
		return -1;
	}

	/* Trim to the first period */
	len = strcspn(frid, ".");
	frid[len] = '\0';

	out->present = true;
	out->value = frid;
	out->len = len;

	return 0;
}
