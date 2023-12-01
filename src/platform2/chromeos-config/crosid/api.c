/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/* High-level entry points for clients which link to libcrosid. */

#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>

#include "crosid.h"

int crosid_get_firmware_manifest_key(char **manifest_key_out)
{
	struct crosid_probed_device_data data;
	int rv;

	*manifest_key_out = NULL;
	rv = crosid_probe(&data);
	if (rv < 0)
		return rv;

	rv = crosid_match(&data);
	if (rv >= 0) {
		/* data.firmware_manifest_key freed by crosid_probe_free */
		*manifest_key_out = strdup(data.firmware_manifest_key);
	}

	crosid_probe_free(&data);
	return rv;
}
