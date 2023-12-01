#!/bin/bash
# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Test secure-wipe.sh scripts.

# Overload basic functions like fio and hdparm, and check the logic of
# secure-wipe.sh.

# Redirect output, we will compare against a golden file.
RESULT_FILE=$(mktemp)
exec >"${RESULT_FILE}"

. ./secure-wipe.sh

declare -i mmc_status_test

dd() {
  echo "${FUNCNAME} : $@"
}

get_device_type() {
  cat "${DEV_TYPE_FILE}"
}

fio() {
  # We knows how fio is called, and that the 4th argument is the output file.
  local f="$3"
  echo "${FUNCNAME} : dev: ${FIO_DEV} - v:${FIO_VERIFY_ONLY}"
  cp "${FIO_OUTPUT}" "${f}"
}

hdparm() {
  if [ "$1" = "-I" ]; then
    cat "${HDPARM_OUTPUT}"
  else
    echo "${FUNCNAME} : $@"
  fi
}

mmc() {
  local mmc_status_test
  if [ "$1" = "status" ]; then
    mmc_status_test=$(cat "${MMC_STATUS_FILE}")
    echo -n "SEND_STATUS response: "
    if [ ${mmc_status_test} -eq 0 ]; then
      echo "0xffffffff"
    else
      : $(( mmc_status_test -= 1))
      echo "0x00000900"
    fi
    echo ${mmc_status_test} >"${MMC_STATUS_FILE}"
  else
    echo "${FUNCNAME} : $@"
  fi
}

blkdiscard() {
  for i; do
    if [ "${i}" = "-s" ]; then
      return 1
    fi
  done
  return 0
}

DEV_TYPE_FILE=$(mktemp)
test_dev="test device"
test_dev_size="$(( 64 * 1048576 ))"

HDPARM_OUTPUT="./tests/kingston.hdparm"
echo "ATA" >"${DEV_TYPE_FILE}"
secure_erase "${test_dev}"

MMC_STATUS_FILE=$(mktemp)
TEST_DELAY=0
TEST_FIO_OUTPUT=$(mktemp)

echo "MMC" >"${DEV_TYPE_FILE}"
# Failed to sanitize
echo "1" >"${MMC_STATUS_FILE}"
secure_erase "${test_dev}"

# Success
echo "-1" >"${MMC_STATUS_FILE}"
secure_erase "${test_dev}"
rm "${MMC_STATUS_FILE}"

FIO_OUTPUT="./tests/fio_good"
perform_fio_op "${test_dev}" "${test_dev_size}" "write"
perform_fio_op "${test_dev}" "${test_dev_size}" "verify"

FIO_OUTPUT="./tests/fio_invalid_character"
perform_fio_op "${test_dev}" "${test_dev_size}" "verify"
FIO_OUTPUT="./tests/fio_invalid_device"
perform_fio_op "${test_dev}" "${test_dev_size}" "verify"

rm "${TEST_FIO_OUTPUT}"

diff "./tests/factory_verify_test.result" "${RESULT_FILE}"
rc=$?
if [ ${rc} -eq 0 ]; then
  rm "${RESULT_FILE}"
else
  echo "Test failed: Output at ${RESULT_FILE}" >&2
fi
exit ${rc}
