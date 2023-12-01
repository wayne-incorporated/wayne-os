#!/bin/sh
# Copyright 2015 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

STATEFUL="/mnt/stateful_partition"

get_stateful_df_data() {
  local bs="${1:-1K}"
  df --block-size "${bs}" -P "${STATEFUL}" | grep -m 1 "${STATEFUL}"
}

# Get the lifetime writes from the stateful partition.
get_stateful_lifetime_writes() {
  local stateful_dev
  stateful_dev="$(rootdev '/mnt/stateful_partition' | sed -e 's#^/dev/##')"
  local lifetime_writes
  lifetime_writes="$(cat "/sys/fs/ext4/${stateful_dev}/lifetime_write_kbytes")"
  : "${lifetime_writes:=0}"
  echo "${lifetime_writes}"
}

# Get the percentage of space used on the stateful partition.
get_stateful_usage_percent() {
  local stateful_space
  stateful_space="$(get_stateful_df_data)"
  # Remove everything after and including the "%"
  stateful_space="${stateful_space%%%*}"
  # Remove all fields except the last one.
  stateful_space="${stateful_space##* }"
  echo "${stateful_space}"
}

# Get the free space on the stateful partition.
#
# inputs:
#   bs        -- size of block as understood by strosize (suffixes allowed)
get_stateful_free_space_blocks() {
  local bs="${1:-1K}"
  get_stateful_df_data "${bs}" | awk '{print $4}'
}

# Get the total space on the stateful partition.
#
# inputs:
#   bs        -- size of block as understood by strosize (suffixes allowed)
get_stateful_total_space_blocks() {
  local bs="${1:-1K}"
  get_stateful_df_data "${bs}" | awk '{print $2}'
}

# Get the used space on the stateful partition.
#
# inputs:
#   bs        -- size of block as understood by strosize (suffixes allowed)
get_stateful_used_space_blocks() {
  local bs="${1:-1K}"
  get_stateful_df_data "${bs}" | awk '{print $3}'
}

# Gets enum for stateful partition's format.
#
# Output denotes the following formats:
#   0 - Raw partition
#   1 - Logical volume (LVM)
get_stateful_format_enum() {
  local stateful_dev
  stateful_dev="$(rootdev '/mnt/stateful_partition')"

  case "${stateful_dev}" in
    /dev/dm*) printf 1 ;;
    *)        printf 0 ;;
  esac
}
