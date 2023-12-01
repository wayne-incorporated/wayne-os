/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <arpa/inet.h> /* for ntohl */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crosid.h"

static int smbios_get_sku_id(uint32_t *out)
{
	char *sku_contents;
	char *endptr;
	size_t sku_len;
	uint32_t sku;

	if (crosid_read_file(SYSFS_SMBIOS_ID_PATH, "product_sku", &sku_contents,
			     &sku_len) < 0)
		return -1;

	/*
	 * Should always start with "sku", have at least one digit,
	 * and end with a trailing newline.
	 */
	if (sku_len < 5 || strncmp(sku_contents, "sku", 3)) {
		crosid_log(LOG_DBG, "SKU file is too short\n");
		goto err;
	}

	sku = strtoll(sku_contents + 3, &endptr, 10);
	if (*endptr != '\n') {
		crosid_log(LOG_DBG, "Extra data at end of SKU file \"%s\"\n",
			   endptr);
		goto err;
	}

	*out = sku;
	free(sku_contents);
	return 0;

err:
	free(sku_contents);
	return -1;
}

static int fdt_get_sku_id(uint32_t *out)
{
	char *sku_contents;
	size_t sku_len;

	if (crosid_read_file(PROC_FDT_COREBOOT_PATH, "sku-id", &sku_contents,
			     &sku_len) < 0)
		return -1;

	if (sku_len != sizeof(*out)) {
		crosid_log(LOG_DBG, "FDT SKU file should always be 4 bytes\n");
		goto err;
	}

	*out = ntohl(*((uint32_t *)sku_contents));
	free(sku_contents);
	return 0;

err:
	free(sku_contents);
	return -1;
}

int crosid_get_sku_id(uint32_t *out, const char **srctype)
{
	if (smbios_get_sku_id(out) == 0) {
		*srctype = "SMBIOS";
		return 0;
	}

	if (fdt_get_sku_id(out) == 0) {
		*srctype = "FDT";
		return 0;
	}

	return -1;
}
