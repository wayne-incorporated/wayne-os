#!/bin/bash
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

DISK_TEMP_TEMPLATE=chromeos-disk-metrics.XXXXXX
DISK_TEMP=$(mktemp -d --tmpdir "${DISK_TEMP_TEMPLATE}")

. chromeos-disk-metrics --test

declare -i id

# Mock output command
metrics_client() {
  echo "metrics_client: $*"
}

run_test() {
  local name=$1
  local out="${DISK_TEMP}/${name}.out"
  local exp_result
  id=$2
  exp_result="tests/${name}_${id}.golden"
  ${name} > "${out}"
  diff "${out}" "${exp_result}"
  if [ $? -ne 0 ]; then
    echo "test_${name} failed"
    exit 1
  fi
}

STORAGE_INFO_FILE="tests/storage_info_1.txt"
run_test sata_disk_metrics 1
run_test emmc_disk_metrics 1
run_test sindin8de2_disk_metrics 1
run_test nvme_disk_metrics 1
run_test ufs_disk_metrics 1

STORAGE_INFO_FILE="tests/storage_info_2.txt"
run_test sata_disk_metrics 2
run_test emmc_disk_metrics 2
run_test sindin8de2_disk_metrics 2
run_test nvme_disk_metrics 2
run_test ufs_disk_metrics 2

STORAGE_INFO_FILE="tests/storage_info_sindin8de2.txt"
run_test sata_disk_metrics 3
run_test emmc_disk_metrics 3
run_test sindin8de2_disk_metrics 3
run_test nvme_disk_metrics 3
run_test ufs_disk_metrics 3

STORAGE_INFO_FILE="tests/storage_info_4.txt"
run_test sata_disk_metrics 4
run_test emmc_disk_metrics 4
run_test sindin8de2_disk_metrics 4
run_test nvme_disk_metrics 4
run_test ufs_disk_metrics 4

STORAGE_INFO_FILE="tests/storage_info_5.txt"
run_test sata_disk_metrics 5
run_test emmc_disk_metrics 5
run_test sindin8de2_disk_metrics 5
run_test nvme_disk_metrics 5
run_test ufs_disk_metrics 5


rm -rf "${DISK_TEMP}"
