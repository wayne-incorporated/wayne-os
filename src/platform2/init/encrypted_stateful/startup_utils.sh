# Copyright 2013 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Give mount-encrypted umount 10 times to retry, otherwise
# it will fail with 'device is busy' because lazy umount does not finish
# clearing all reference points yet. Check crosbug.com/p/21345.
umount_var_and_home_chronos() {
  # Check if the encrypted stateful partition is mounted.
  if ! mountpoint -q "/mnt/stateful_partition/encrypted"; then
    return 0
  fi

  local rc=0
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    mount-encrypted umount
    rc="$?"
    if [ "${rc}" -eq "0" ]; then
      break
    fi
    sleep 0.1
  done
  return "${rc}"
}
