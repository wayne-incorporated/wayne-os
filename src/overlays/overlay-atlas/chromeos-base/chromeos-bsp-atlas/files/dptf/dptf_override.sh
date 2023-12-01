#!/bin/sh
#
# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Select dptf configuration based on the following criteria.
# - CPU model name
# - DRAM part number prefix
# - DRAM capacity
#
# Documentation: http://go/atlas-dptf-override
#

dptf_get_override() {
  local dram_part=
  local cpu_model=
  local memtotal_kib=
  local memtotal_gib=
  local dptf_file=

  cpu_model="$(uname -p | grep -o "[im][357]")"
  dram_part="$(mosys memory spd print id -s part_number | grep -om1 ^..)"
  memtotal_kib="$(grep '^MemTotal:' /proc/meminfo | grep -oE '[0-9]+')"
  # Atlas should have even GiB of RAM.  Round up to nearest even number.
  memtotal_gib="$(( (((memtotal_kib >> 20) + 1) / 2) * 2 ))"

  cpu_dram="$(echo "${cpu_model}-${dram_part}-${memtotal_gib}")"

  case "${cpu_dram}" in
    m3-K4-8)  dptf_file="0987_8765.bin" ;;
    m3-MT-8)  dptf_file="1098_0987.bin" ;;
    i5-K4-8)  dptf_file="0987_9876.bin" ;;
    i5-MT-8)  dptf_file="1098_0987.bin" ;;
    i5-K4-16) dptf_file="0987_9876.bin" ;;
    i5-MT-16) dptf_file="1199_0886.bin" ;;
    i7-K4-16) dptf_file="1199_0886.bin" ;;
    i7-MT-16) dptf_file="1199_1098.bin" ;;
  esac

  echo "${dptf_file}"
}
