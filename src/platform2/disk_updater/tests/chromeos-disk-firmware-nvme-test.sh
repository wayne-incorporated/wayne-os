#!/bin/bash
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Chrome OS Disk Firmware Update Script test harness
# Use bash to be able to source the script to test with parameters and
# use array:
# !bash -x ./scripts/chromeos-disk-firmware-test.sh > /tmp/test 2>&1
#
# Works only in the chromium chroot.

export LC_ALL=C
DISK_TEMP_TEMPLACE=test_fw.XXXXXX
DISK_TEMP=$(mktemp -d --tmpdir "${DISK_TEMP_TEMPLACE}")


# source the script to test: The test script is in bash to
# allow paramters to be taken into account.
. scripts/chromeos-disk-firmware-update.sh \
  --tmp_dir "${DISK_TEMP}" \
  --fw_package_dir "tests/test_nvme_dir" \
  --nvme "tests/nvme" \
  --test

# Read the identify for files
declare -a nvme_model
declare -a nvme_fwrev
declare -a nvme_rc
declare -i id_idx

disk_nvme_id_info() {
  local rc=${nvme_id_rc[${id_idx}]}
  if [ "${rc}" -eq 0 ]; then
    cat "tests/${nvme_id_files[${id_idx}]}.nvme"
  fi
  : $(( id_idx += 1))
  return "${rc}"
}

prepare_test() {
  id_idx=0
  find "${DISK_TEMP}" -mindepth 1 -delete
}

run_test() {
  main > "${DISK_TEMP}/result"
}

check_test() {
  local test_id=$1
  local exp_result=$2_${test_id}
  local test_exp_rc=$3
  local test_rc=$4
  if [ "${test_exp_rc}" -ne "${test_rc}" ]; then
    echo "Expected ${test_exp_rc}, got ${test_rc}"
    exit 1
  fi
  diff "${DISK_TEMP}/result" "tests/${exp_result}"
  if [ $? -ne 0 ]; then
    echo "test_${test_id} failed"
    exit 1
  fi
}

# NVME tests:
get_device_type() {
  echo "NVME"
}

list_fixed_ata_disks() {
  echo
}

list_fixed_mmc_disks() {
  echo
}

list_fixed_nvme_disks() {
  echo "nvme0"
}

disk_nvme_current_slot() {
  echo "    1"
}

# Upgrade with reset.
prepare_test
nvme_id_files=(
  'INTEL_SSDPEKKW256G7-PSF101C'
  ''
  ''
  'INTEL_SSDPEKKW256G7-PSF109C'
  'INTEL_SSDPEKKW256G7-PSF109C'
)
nvme_id_rc=(0 10 10 0 0)

disk_nmve_reset() {
  echo "mock reset for $1"
}

run_test
check_test 1 nvme_upgraded 0 $?
echo NVME PASS 1

prepare_test
nvme_id_files=(
  'INTEL_SSDPEKKW256G7-PSF109C'
)
nvme_id_rc=(0)

run_test
check_test 2 nvme_good 0 $?
echo NVME PASS 2

# set firmware upgrade to fail
disk_nmve_reset() {
  return 1
}

prepare_test
nvme_id_files=(
  'INTEL_SSDPEKKW256G7-PSF101C'
)
nvme_id_rc=(0)
run_test
check_test 3 nvme_upgrade_failed 1 $?
echo NVME PASS 3

# Upgrade without reset.
prepare_test
nvme_id_files=(
  'INTEL_SSDPEKKW256G7-PSF100C'
  ''
  ''
  'INTEL_SSDPEKKW256G7-PSF109C'
  'INTEL_SSDPEKKW256G7-PSF109C'
)
nvme_id_rc=(0 10 10 0 0)

run_test
check_test 4 nvme_upgraded 0 $?
echo NVME PASS 4

# Upgrade Samsung device
prepare_test
nvme_id_files=(
  'SAMSUNG_KUS040205M-DXC81G1E'
  'SAMSUNG_KUS040205M-DXC81G1T'
  'SAMSUNG_KUS040205M-DXC81G1T'
)
nvme_id_rc=(0 0 0)
run_test
check_test 5 nvme_upgraded 0 $?
echo NVME PASS 5

disk_nmve_reset() {
  echo "mock reset for $1"
}

# Upgrade BH799 device
prepare_test
nvme_id_files=(
  'BAYHUB-HynixhC8aP_303064GB-Disk-10100050'
  'BAYHUB-HynixhC8aP_303064GB-Disk-10100065'
  'BAYHUB-HynixhC8aP_303064GB-Disk-10100065'
)
nvme_id_rc=(0 0 0)
run_test
check_test 6 nvme_upgraded 0 $?
echo NVME PASS 6

rm -rf "${DISK_TEMP}"
