#!/bin/bash

# Copyright 2013 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Unit tests for capture_utility.sh

expect_eq ()
{
  local name="${1}"
  local expected_value="${2}"
  local -a actual_value=(${3})

  if [[ "${expected_value}" != "${actual_value[@]}" ]] ; then
    fatal_error "${name}: is ${actual_value} instead of ${expected_value}"
  fi
}

test_configure_monitor ()
{
  iw () {
    if [[ "$#" != 5 || "${*}" != "dev int0 set freq 1000" ]] ; then
      fatal_error "Unexpected arguments to iw: $*"
    fi
  }
  $(configure_monitor int0 1000)
  iw () {
    if [[ "$#" != 6 || "${*}" != "dev int1 set freq 2000 HT40+" ]] ; then
      fatal_error "Unexpected arguments to iw: $*"
    fi
  }
  $(configure_monitor int1 2000 above)
  iw () {
    if [[ "$#" != 6 || "${*}" != "dev int2 set freq 3000 HT40-" ]] ; then
      fatal_error "Unexpected arguments to iw: $*"
    fi
  }
  $(configure_monitor int2 3000 below)
  iw () {
    if [[ "$#" != 6 || "${*}" != "dev int2 set freq 5000 80MHz" ]]; then
      fatal_error "Unexpected arguments to iw: $*"
    fi
  }
  $(configure_monitor int2 5000 "" 80)
  iw () {
    if [[ "$#" != 7 || "${*}" != "dev int2 set freq 5252 160 5250" ]]; then
      fatal_error "Unexpected arguments to iw: $*"
    fi
  }
  $(configure_monitor int2 5252 "" 160)
  iw () {
    fatal_error "Unexpected iw execution"
  }
  expect_eq "bad 160 channel" "" "$(configure_monitor int2 5160 "" 160)"
}

test_create_monitor ()
{
  iw () {
    if [[ "$#" != 7 ||
          "${*}" != "phy phy0 interface add phy0_mon type monitor" ]] ; then
      fatal_error "Unexpected arguments to iw: $*"
    fi
  }
  ip () {
    if [[ "$#" != 4 || "${*}" != "link set phy0_mon up" ]] ; then
      fatal_error "Unexpected arguments to ip: $*"
    fi
  }
  expect_eq "create_monitor phy" "phy0_mon" "$(create_monitor phy0)"
}

test_device_list ()
{
  ip () {
    if [[ "$#" != 3 || "${*}" != "-o link show" ]] ; then
      fatal_error "Unexpected arguments to ip: $*"
    fi
    printf "1: int0: something\n2: int2:\n"
  }
  local -a devices=($(get_device_list))
  if [[ "${#devices[@]}" != 2 || "${devices[0]}" != "int0" ||
        "${devices[1]}" != "int2" ]] ; then
    fatal_error "Unexpected device list (size ${#devices[@]}): ${devices[@]}"
  fi
}

test_get_devices_for_phy ()
{
  iw () {
    if [[ "$#" != 1 || "${1}" != "dev" ]] ; then
      fatal_error "Unexpected arguments to iw: $*"
    fi
    echo -e "phy#0\n\tInterface phy0_mon\n\t\ttype monitor"
    echo -e "phy#1\n\tInterface phy1_managed\n\t\ttype managed"
    echo -e "\tInterface phy1_mon\n\t\ttype monitor"
    echo -e "phy#2"
  }
  expect_eq "phy0 devices" "phy0_mon" "$(get_devices_for_phy 0)"
  expect_eq "phy1 devices" "phy1_managed phy1_mon" "$(get_devices_for_phy phy1)"
  expect_eq "phy2 devices" "" "$(get_devices_for_phy 2)"
}

test_get_ht_info ()
{
  iw () {
    if [[ "$#" != 4 || "${1}" != "dev" || "${2}" != "int0" ||
          "${3}" != "scan" || "${4}" != "dump" ]] ; then
      fatal_error "Unexpected arguments to iw: $*"
    fi
    echo -e 'BSS 00:11:22(on wlan0) -- associated' \
            '\n\tfreq: 1000\n\t\* secondary channel offset: above'
    echo -e 'BSS 33:44:55\n\tfreq: 2000\n\t\* secondary channel offset: below'
    echo -e 'BSS 66:77:88\n\tfreq: 3000\n\t\* secondary channel offset: no'
    echo -e 'BSS 99:aa:bb\n\tfreq: 4000'
  }
  expect_eq "ht info 1000" "above" "$(get_ht_info int0 00:11:22 1000)"
  expect_eq "ht info 2000" "below" "$(get_ht_info int0 33:44:55 2000)"
  expect_eq "ht info 3000" "" "$(get_ht_info int0 66:77:88 3000)"
  expect_eq "ht info 4000" "" "$(get_ht_info int0 99:aa:bb 4000)"
}

test_get_link_info ()
{
  iw () {
    if [[ "$#" != 3 || "${1}" != "dev" || "${3}" != "link" ]] ; then
      fatal_error "Unexpected arguments to iw: $*"
    fi
    local device="${2}"
    if [[ "${device}" == "int0" ]] ; then
      return
    elif [[ "${device}" == "int1" ]] ; then
      echo -e 'Connected to 00:11:22\n\tfreq: 1000'
    else
      fatal_error "Unexpected device argument to iw: ${device}"
    fi
  }
  expect_eq "int0 link info" "" "$(get_link_info int0)"
  expect_eq "int1 link info" "00:11:22 1000" "$(get_link_info int1)"
}

test_get_monitor_device ()
{
  # Only one device exists, and is already in monitor mode.
  get_device_list () {
    echo int0
  }
  get_phy_info () {
    echo "monitor 0"
  }
  configure_monitor () {
    return 1
  }
  # Since configure_monitor failed.
  expect_eq "Device from failed configure" "" "$(get_monitor_device 1000)"

  configure_monitor () {
    return
  }

  # Successful configure_monitor of first available device.
  # Since configure_monitor failed.
  expect_eq "Device from good configure" "int0" "$(get_monitor_device 1000)"

  get_monitor_phy_list () {
    echo phy0
  }

  # Only available device is also on the phy we are looking for.
  expect_eq "Only device" "int0" "$(get_monitor_device 1000 "" "" 0)"

  create_monitor () {
    echo "${1}_mon"
  }
  get_phy_info () {
    echo "managed 0"
  }

  # Create a monitor device on the shared phy.
  expect_eq \
      "Created monitor dev" "phy0_mon" "$(get_monitor_device 1000 "" "" 0)"

  get_monitor_phy_list () {
    echo phy0 phy1
  }
  configure_monitor () {
    if [[ "${1}" != "phy0_mon" ]] ; then
      return 1
    fi
  }

  iw () {
    if [[ "$@" != "dev phy1_mon del" ]] ; then
      fatal_error "Unexpected iw args"
    fi
  }

  # Presented with another phy, we try that first but fail.
  expect_eq "Created monitor #2" "phy0_mon" "$(get_monitor_device 1000 "" "" 0)"
}

test_get_monitor_on_phy()
{
  # A monitor device already exists for the phy.
  get_device_list() {
    echo "phy0_mon"
  }
  get_phy_info() {
    echo "monitor 0"
  }
  create_monitor() {
    true
  }
  expect_eq "Monitor device" "phy0_mon" "$(get_monitor_on_phy 0)"

  # A monitor device exists, but does not match.
  get_device_list() {
    echo "phy1_mon"
  }
  get_phy_info() {
    echo "monitor 1"
  }
  create_monitor() {
    echo "phy0_mon"
  }
  expect_eq "Monitor device" "phy0_mon" "$(get_monitor_on_phy 0)"

  # A monitor device exists, but does not match. Additionally,
  # creating a new monitor fails.
  get_device_list() {
    echo "phy1_mon"
  }
  get_phy_info() {
    echo "monitor 1"
  }
  create_monitor() {
    return
  }
  expect_eq "Monitor device" "" "$(get_monitor_on_phy 0)"
}

test_get_monitor_for_link ()
{
  # Fail because device is not in managed mode.
  get_phy_info () {
    echo "mumble 0"
  }
  expect_eq "Non-managed phy" "" "$(get_monitor_for_link int0)"

  # Fail because device is not connected.
  get_phy_info () {
    echo "managed 0"
  }
  get_link_info () {
    return
  }
  expect_eq "No link exists" "" "$(get_monitor_for_link int0)"

  # Fail because monitor device could not be found/created.
  get_link_info () {
    echo "00:11:22 1000"
  }
  get_width () {
    echo "40"
  }
  get_ht_info () {
    echo "above"
  }
  get_monitor_device () {
    return
  }
  expect_eq "get_monitor_device failed" "" "$(get_monitor_for_link int0)"

  # Success: get_monitor_device gives us a device.
  get_monitor_device () {
    expect_eq "get_monitor_device args" "1000 above 40 0" "${*}"
    echo "mon0"
  }
  expect_eq "get_monitor_device succeeded" "mon0" "$(get_monitor_for_link int0)"

  # Success: get_monitor_device fails, but get_monitor_on_phy succeeds.
  get_monitor_device () {
    return 1
  }
  get_monitor_on_phy() {
    echo "mon0"
  }
  expect_eq "get_monitor_device succeeded" "mon0" "$(get_monitor_for_link int0)"

  # Failure: we fail to configure |int1| to monitor the connection of |int0|.
  configure_monitor () {
    return 1
  }
  expect_eq "configure failed" "" "$(get_monitor_for_link int0 int1)"

  # Success: we configure |int1| to monitor the connection of |int0|.
  configure_monitor () {
    return 0
  }
  expect_eq "configure succeeded" "int1" "$(get_monitor_for_link int0 int1)"
}

test_get_monitor_phy_list ()
{
  iw () {
    if [[ "$#" != 1 || "${1}" != "phy" ]] ; then
      fatal_error "Unexpected arguments to iw: $*"
    fi
    echo -e 'Wiphy phy0\n\t* 1000 MHz\n\t\t * monitor'
    echo -e 'Wiphy phy1\n\t* 1000 MHz\n\t\t * station'
    echo -e 'Wiphy phy2\n\t* 2000 MHz\n\t\t * monitor'
    echo -e 'Wiphy phy3\n\t* 2000 MHz\n\t\t * monitor'
  }
  expect_eq "phys for frequency 1000" "phy0" "$(get_monitor_phy_list 1000)"
  expect_eq "phys for frequency 2000" "phy2 phy3" "$(get_monitor_phy_list 2000)"
}

test_get_phy_info ()
{
  local device=dev0
  local dtype=travis
  local wiphy=199
  iw () {
    if [[ "$#" != 3 || "${1}" != "dev" || "${2}" != "${device}" ||
          "${3}" != "info" ]] ; then
      fatal_error "Unexpected arguments to iw: $*"
    fi
    echo -e "Interface ${device}\n\ttype ${dtype}\n\twiphy ${wiphy}"
  }
  expect_eq "Phy info" "${dtype} ${wiphy}" "$(get_phy_info ${device})"
}

test_get_array_size ()
{
  expect_eq "empty list" "0" "$(get_array_size)"
  expect_eq "single entry list" "1" "$(get_array_size 1)"
  expect_eq "double entry list" "2" "$(get_array_size 1 "number two")"
}

test_get_array_element ()
{
  local list="a b c d e"
  expect_eq "first element" "a" "$(get_array_element 1 $list)"
  expect_eq "second element" "b" "$(get_array_element 2 $list)"
  expect_eq "third element" "c" "$(get_array_element 3 $list)"
}

test_get_center_freq ()
{
  expect_eq "Nothing" "" "$(get_center_freq "5170")"
  expect_eq "channel 50 (5250)" "5250" "$(get_center_freq "5180")"
  expect_eq "Nothing" "" "$(get_center_freq "5340")"
  expect_eq "channel 114 (5570)" "5570" "$(get_center_freq "5580")"
  expect_eq "Nothing" "" "$(get_center_freq "7000")"
}

test_get_width ()
{
  local device=dev0
  local statype=monitor
  iw () {
    if [[ "$#" != 3 || "${1}" != "dev" || "${2}" != "${device}" ||
          "${3}" != "info" ]]; then
      fatal_error "Unexpected arguments to iw: $*"
    fi
    printf "\ttype ${statype}\n"
    echo "channel 36 (5180 MHz), width: 160 MHz, center1: 5250 MHz"
  }
  statype=monitor
  expect_eq "Monitor mode" "" "$(get_width "${device}")"
  statype=managed
  expect_eq "Managed mode" "160" "$(get_width "${device}")"
}

main ()
{
  # Load the capture utility functions.  Set the command line to something
  # innocuous so the capture main function returns cleanly without exiting.
  set -- --help
  . $(dirname $0)/capture_utility.sh >/dev/null

  # Since these tests work mostly by mocking out functions, we should
  # run each test in its own subshell.
  local ret=0
  for test in \
      configure_monitor \
      create_monitor \
      device_list \
      get_devices_for_phy \
      get_ht_info \
      get_link_info \
      get_monitor_device \
      get_monitor_for_link \
      get_monitor_on_phy \
      get_monitor_phy_list \
      get_phy_info \
      get_array_size \
      get_array_element \
      get_center_freq \
      get_width; do
    if (test_${test}) ; then
      echo "Passed: $test"
    else
      echo "Failed: $test"
      ret=1
    fi
  done
  return $ret
}

set -e
main
