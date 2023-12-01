#!/bin/bash
# Copyright 2014 The ChromiumOS Authors
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
  --fw_package_dir "tests/test_mmc_dir" \
  --mmc "tests/mmc" \
  --test

# Overwrite funtions that call hdparm
# Read the identify for files
declare -a mmc_model
declare -a mmc_fwrev
declare -a mmc_rc
declare -i id_idx

disk_mmc_info() {
  disk_model="$(echo ${mmc_model[${id_idx}]} | \
                tr -d '\n' | od -t x1 -A none -v | sed 's/ //g')"
  disk_fw_rev="${mmc_fwrev[${id_idx}]}"
  : $(( id_idx += 1))
  return 0
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
  if [ ${test_exp_rc} -ne ${test_rc} ]; then
    echo "Expected ${test_exp_rc}, got ${test_rc}"
    exit 1
  fi
  diff "${DISK_TEMP}/result" "tests/${exp_result}"
  if [ $? -ne 0 ]; then
    echo "test_${test_id} failed"
    exit 1
  fi
}

# MMC tests:
get_device_type() {
  echo "MMC"
}

list_fixed_ata_disks() {
  echo
}

list_fixed_mmc_disks() {
  echo "mmcblk0"
}

list_fixed_nvme_disks() {
  echo
}

prepare_test

mmc_fwrev=(
  '0x0b00000000000000'
  '0xff00000000000000'
  '0xff00000000000000'
  '00'
  '0x0c00000000000000'
  '0xfe00000000000000'
  '0xfe00000000000000'
  '0x3536323330613137'
  '0x3739323330363138'
  '0x3739323330363138'
  '0x0b00000000000000'
  '0xff00000000000000'
)
mmc_model=(
  'MAG2GC'
  'MAG2GC'
  'MAG2GC'
  'NO FFU'
  'MAG3GC'
  'MAG3GC'
  'MAG3GC'
  'DA4032'
  'DA4032'
  'DA4032'
  'MAG2GC'
  'MAG2GC'
)

run_test
check_test 1 mmc_upgraded 0 $?
echo MMC PASS 1

run_test
check_test 2 mmc_good 0 $?
echo MMC PASS 2

run_test
check_test 3 mmc_upgraded 0 $?
echo MMC PASS 3

run_test
check_test 4 mmc_upgraded 0 $?
echo MMC PASS 4

# set firmware upgrade to fail
disk_mmc_upgrade() {
  return 1
}

run_test
check_test 5 mmc_upgrade_failed 1 $?
echo MMC PASS 5


rm -rf "${DISK_TEMP}"
