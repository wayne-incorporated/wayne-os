/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crosid.h"

static int read_optional_string(const char *dir, const char *name,
				struct crosid_optional_string *out)
{
	char *value;
	size_t len;

	if (crosid_read_file(dir, name, &value, &len) < 0) {
		out->present = false;
		out->value = NULL;
		out->len = 0;
		return -1;
	}

	/* Strip a trailing newline, if it exists */
	if (len > 0 && value[len - 1] == '\n') {
		len--;
		value[len] = '\0';
	}

	out->present = true;
	out->value = value;
	out->len = len;

	return 0;
}

static int read_custom_label_tag(struct crosid_probed_device_data *out)
{
	int rv;

	/* Newer devices may use custom_label_tag VPD entry */
	rv = read_optional_string(SYSFS_VPD_RO_PATH, "custom_label_tag",
				  &out->custom_label_tag);
	if (rv >= 0)
		return rv;

	/* If that's not specified, then try whitelabel_tag */
	return read_optional_string(SYSFS_VPD_RO_PATH, "whitelabel_tag",
				    &out->custom_label_tag);
}

int crosid_probe(struct crosid_probed_device_data *out)
{
	const char *sku_src;

	/* To be later populated by crosid_match */
	out->firmware_manifest_key = NULL;

	if (crosid_get_sku_id(&out->sku_id, &sku_src) >= 0) {
		out->has_sku_id = true;
		crosid_log(LOG_DBG, "Read SKU=%u (from %s)\n", out->sku_id,
			   sku_src);
	} else {
		out->has_sku_id = false;
		crosid_log(LOG_DBG,
			   "System has no SKU ID (this is normal on some "
			   "models, especially older ones)\n");
	}

	if (crosid_probe_frid(&out->frid) >= 0) {
		crosid_log(LOG_DBG, "Read FRID \"%s\"\n", out->frid.value);
	} else {
		crosid_log(LOG_DBG, "Device has no FRID\n");
	}

	if (read_optional_string(SYSFS_VPD_RO_PATH, "customization_id",
				 &out->customization_id) >= 0) {
		crosid_log(LOG_DBG, "Read customization_id=\"%s\" (from VPD)\n",
			   out->customization_id.value);
	} else {
		crosid_log(LOG_DBG,
			   "Device has no customization_id (this is to be "
			   "expected on models released in 2018 and later)\n");
	}

	if (read_custom_label_tag(out) >= 0) {
		crosid_log(LOG_DBG, "Read custom_label_tag=\"%s\" (from VPD)\n",
			   out->custom_label_tag.value);
	} else {
		crosid_log(LOG_DBG,
			   "Device has no custom_label_tag (this is to be "
			   "expected, except of custom label devices)\n");
	}

	if (out->customization_id.present && out->custom_label_tag.present) {
		crosid_log(LOG_ERR, "Device has both a customization_id and a "
				    "custom_label_tag. VPD invalid?\n");
		crosid_probe_free(out);
		memset(out, 0, sizeof(*out));
		return -1;
	}

	return 0;
}

static void print_val(FILE *out, const char *key, const char *filter,
		      const char *format, ...)
{
	if (filter && strcmp(filter, key))
		return;

	if (!filter)
		fprintf(out, "%s='", key);

	va_list args;
	va_start(args, format);
	vfprintf(out, format, args);
	va_end(args);

	if (!filter)
		fprintf(out, "'\n");
}

void crosid_print_vars(FILE *out, const char *filter,
		       struct crosid_probed_device_data *data, int config_idx)
{
	if (data->has_sku_id)
		print_val(out, "SKU", filter, "%u", data->sku_id);
	else
		print_val(out, "SKU", filter, "none");

	if (config_idx >= 0)
		print_val(out, "CONFIG_INDEX", filter, "%d", config_idx);
	else
		print_val(out, "CONFIG_INDEX", filter, "unknown");

	print_val(out, "FIRMWARE_MANIFEST_KEY", filter, "%s",
		  data->firmware_manifest_key ? data->firmware_manifest_key :
						"");
}

void crosid_probe_free(struct crosid_probed_device_data *data)
{
	free(data->frid.value);
	free(data->custom_label_tag.value);
	free(data->customization_id.value);
	free(data->firmware_manifest_key);
}
