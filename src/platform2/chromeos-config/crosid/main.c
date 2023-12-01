/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "crosid.h"

#define HELP_MSG                                                                              \
	"Usage: %s [options...]\n"                                                            \
	"\n"                                                                                  \
	"Options:\n"                                                                          \
	"  -h, --help              Show this help message and exit\n"                         \
	"  -v, --verbose           Print debug messages to stderr that can help diagnose\n"   \
	"                          identity probe errors\n"                                   \
	"  -f, --filter KEY        Print only the value matching KEY, no shell quoting\n"     \
	"  --sku-id SKU            Override the SKU number (used by factory process)\n"       \
	"  --custom-label-tag TAG  Override the custom label tag (used by factory process)\n" \
	"  --sysroot SYSROOT       Specify an alternative root directory for testing\n"

static void print_help(const char *prog_name)
{
	fprintf(stderr, HELP_MSG, prog_name);
}

enum long_only_options {
	OPT_SYSROOT = 0x100,
	OPT_SKU_ID,
	OPT_CUSTOM_LABEL_TAG,
};

int main(int argc, char *argv[])
{
	bool help_requested = false;
	int opt;
	int log_level = 0;
	struct option long_opts[] = {
		{
			.name = "help",
			.val = 'h',
		},
		{
			.name = "verbose",
			.val = 'v',
		},
		{
			.name = "filter",
			.has_arg = required_argument,
			.val = 'f',
		},
		{
			.name = "sku-id",
			.has_arg = required_argument,
			.val = OPT_SKU_ID,
		},
		{
			.name = "custom-label-tag",
			.has_arg = required_argument,
			.val = OPT_CUSTOM_LABEL_TAG,
		},
		{
			.name = "sysroot",
			.has_arg = required_argument,
			.val = OPT_SYSROOT,
		},
	};
	const char *filter = NULL;
	struct crosid_probed_device_data device_data;
	int matched_config_index;
	bool has_sku_id_override = false;
	uint32_t sku_id_override;
	char *endptr;
	char *custom_label_tag_override = NULL;

	while ((opt = getopt_long(argc, argv, ":hvf:", long_opts, NULL)) !=
	       -1) {
		switch (opt) {
		case 'h':
			help_requested = true;
			break;
		case 'v':
			log_level++;
			break;
		case 'f':
			filter = optarg;
			break;
		case OPT_SYSROOT:
			crosid_set_sysroot(optarg);
			break;
		case OPT_SKU_ID:
			sku_id_override = strtoul(optarg, &endptr, 0);
			if (!optarg[0] || endptr[0]) {
				crosid_log(
					LOG_ERR,
					"Invalid argument for --sku-id: %s\n",
					optarg);
				print_help(argv[0]);
				return 1;
			}
			has_sku_id_override = true;
			break;
		case OPT_CUSTOM_LABEL_TAG:
			custom_label_tag_override = strdup(optarg);
			break;
		default:
			crosid_log(LOG_ERR, "Unknown argument: %s\n",
				   argv[optind - 1]);
			print_help(argv[0]);
			return 1;
		}
	}

	crosid_set_log_level(log_level);

	if (optind < argc) {
		crosid_log(LOG_ERR, "Unknown argument: %s\n", argv[optind]);
		print_help(argv[0]);
		return 1;
	}

	if (help_requested) {
		print_help(argv[0]);
		return 0;
	}

	if (crosid_probe(&device_data) < 0)
		return 1;

	if (has_sku_id_override) {
		device_data.has_sku_id = true;
		device_data.sku_id = sku_id_override;
	}

	if (custom_label_tag_override) {
		device_data.custom_label_tag.present = true;
		device_data.custom_label_tag.value = custom_label_tag_override;
	}

	matched_config_index = crosid_match(&device_data);
	crosid_print_vars(stdout, filter, &device_data, matched_config_index);
	crosid_probe_free(&device_data);
	return matched_config_index < 0;
}
