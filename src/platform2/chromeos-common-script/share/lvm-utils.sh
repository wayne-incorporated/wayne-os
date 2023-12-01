#!/bin/sh
# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This script contains common helper functions to use with LVM-based stateful
# partitions. These helpers are useful for both install and startup
# scripts.

# Fetches the volume group name on the device. Empty if the device is not a
# valid physical volume or if it doesn't have a volume group set up on it.
get_volume_group() {
  local physical_volume="$1"

  pvs --quiet --readonly --noheadings --separator '|' \
    -o vg_name "${physical_volume}" | tr -d '[:space:]'
}

# Generate a random label, used for volume group name generation.
generate_random_label() {
 local n
 for n in $(od -A none -tu1 -N16 /dev/urandom); do
   # 36 doesn't evenly divide 256 so there's slight bias here.
   n=$(( n % 36 ))
   if [ "${n}" -lt "10" ]; then
     # shellcheck disable=SC2059
     printf "${n}"
   else
     # shellcheck disable=SC2059
     printf "\\$(printf '%03o' $((n - 10 + 0x41)))"
   fi
 done
}

# Try to validate the volume group name: if another volume group exists with the
# same name, regenerate the volume group name. Bail out after 5 tries.
generate_random_vg_name() {
  local vg_name
  local _

  for _ in 1 2 3 4 5; do
    vg_name="$(generate_random_label)"
    # If there is no volume group on the device with the generated vg name
    # return.
    if ! vgs "${vg_name}" >/dev/null; then
      # shellcheck disable=SC2059
      printf "${vg_name}"
      return
    fi
  done
}

# Gets device size in bytes.
get_device_size() {
  local device="$1"
  blockdev --getsize64 "${device}"
}

# With multiple logical volumes per user, we need more than 1 physical extent to
# store the physical volume metadata. Therefore, there may not be enough space
# to store the data for O(100) logical volumes. We set aside 4 physical extents
# (the default PE size is 4MB). Additionally, we need to set aside some space
# the thinpool's metadata. thin_metadata_size estimates the metadata size for
# storing a maximum of 200 logical volumes as <2% of the size of the thinpool.
get_thinpool_size() {
  local physical_volume="$1"
  echo $(( $(get_device_size "${physical_volume}") * 98 / (100 * 1024 * 1024) ))
}

# Thin provisioning tools uses a util to calculate what the metadata size should
# for give a device and maximum number of thinpools associated with the device.
get_thinpool_metadata_size() {
  local thinpool_size="$1"

  thin_metadata_size --block-size 4k --pool-size "${thinpool_size}M" \
      --max-thins 200 --numeric-only -u M
}

# By default, create thin logical volumes at 95% of the size of the thinpool.
get_logical_volume_size() {
  local physical_volume="$1"
  local thinpool_size

  thinpool_size="$(get_thinpool_size "${physical_volume}")"
  echo $(( thinpool_size * 95 / 100 ))
}
