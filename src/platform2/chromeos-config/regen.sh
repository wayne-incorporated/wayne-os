#!/bin/sh
# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Convenience script to regenerate all auto-generated files (test
# data, README.md, power manager schema).

set -e

# Change to the directory of this script.
cd "$(dirname "$0")"

# Regen power manager prefs schema
python3 -m cros_config_host.power_manager_prefs_gen_schema \
        -o cros_config_host/power_manager_prefs_schema.yaml

# Regen README (must come after power manager prefs, as this can
# affect the schema content)
python3 -m cros_config_host.generate_schema_doc -o README.md

python3 -m cros_config_host.cros_config_schema -c test_data/test_import.yaml \
        -o test_data/test_import.json
python3 -m cros_config_host.cros_config_schema -o test_data/test_merge.json \
        -m test_data/test_merge_base.yaml test_data/test_merge_overlay.yaml
python3 -m cros_config_host.cros_config_schema -o test_data/test_build.json \
        -m test_data/test.yaml
python3 -m cros_config_host.cros_config_schema --zephyr-ec-configs-only \
        -o test_data/test_zephyr.json -m test_data/test.yaml

regen_test_data() {
    python3 -m cros_config_host.cros_config_schema -f True \
            -c "test_data/${1}.yaml" -o "test_data/${1}.json"
}

# ARM test data
regen_test_data test_arm

# x86 test data
regen_test_data test

# Regen proto_converter test data.
python3 -m cros_config_host.cros_config_proto_converter --regen
