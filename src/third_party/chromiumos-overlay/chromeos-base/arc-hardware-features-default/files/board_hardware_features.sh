#!/bin/sh
# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Customization script to modify a board hardware feature list, based on
# /etc/hardware_features.xml. Read go/arc-board-features and
# go/arc-hardware-features-default for how to use this file.

die() {
  echo "ERROR: $1" >&2
  exit 1
}

modify_feature() {
  local file="$1"
  local feature="$2"
  local pattern="$3"
  local replace="$4"

  # Assume each feature is already defined in one line.
  sed -e "/name=\"${feature}\"/s/${pattern}/${replace}/" -i "${file}"
}

enable_feature() {
  modify_feature "$@" "<unavailable-feature " "<feature "
}

disable_feature() {
  modify_feature "$@" "<feature " "<unavailable-feature "
}

has_hardware_property() {
  [ "$(/usr/bin/cros_config /hardware-properties "$1")" = "true" ]
}

has_accelerometer() {
  has_hardware_property has-base-accelerometer ||
      has_hardware_property has-lid-accelerometer
}

has_compass() {
  has_hardware_property has-base-magnetometer ||
      has_hardware_property has-lid-magnetometer
}

has_gyro() {
  has_hardware_property has-base-gyroscope ||
      has_hardware_property has-lid-gyroscope
}

has_light_sensor () {
  has_hardware_property has-base-light-sensor ||
      has_hardware_property has-lid-light-sensor
}

has_multicamera() {
  local camera_count
  camera_count="$(/usr/bin/cros_config /camera count)"
  [ "${camera_count}" = "2" ]
}

has_touchscreen() {
  has_hardware_property has-touchscreen
}

check_feature() {
  local callback="$1"
  local file="$2"
  local property="android.hardware.$3"

  if "${callback}"; then
    echo "Enable feature: ${property##*.}"
    enable_feature "${file}" "${property}"
  else
    echo "Disable feature: ${property##*.}"
    disable_feature "${file}" "${property}"
  fi
}

main() {
  if [ "$#" != 1 ]; then
    die "Usage: board_hardware_features PATH_TO_PLATFORM_XML"
  fi
  local file="$1"

  check_feature has_accelerometer "${file}" sensor.accelerometer
  check_feature has_compass "${file}" sensor.compass
  check_feature has_gyro "${file}" sensor.gyroscope
  check_feature has_light_sensor "${file}" sensor.light
  check_feature has_multicamera "${file}" camera
  check_feature has_multicamera "${file}" camera.autofocus
  check_feature has_touchscreen "${file}" touchscreen
  check_feature has_touchscreen "${file}" touchscreen.multitouch
  check_feature has_touchscreen "${file}" touchscreen.multitouch.distinct
  check_feature has_touchscreen "${file}" touchscreen.multitouch.jazzhand
}

main "$@"
