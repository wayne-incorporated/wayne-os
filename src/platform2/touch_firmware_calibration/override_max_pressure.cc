// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/* override_max_pressure: This command line tool is designed to override the max
 * pressure of the target device under /dev/input/
 * Usage:
 * $override_max_pressure --device=event4 --maxpressure=2048
 */
#include <linux/input.h>
#include <iostream>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <base/logging.h>
#include <brillo/flag_helper.h>

int main(int argc, char** argv) {
  DEFINE_string(device, "", "Path of the device");
  DEFINE_int32(maxpressure, -1, "Max pressure to override.");

  brillo::FlagHelper::Init(
      argc, argv, "override_stylus_pressure, Override max pressure of device.");

  if (FLAGS_device == "") {
    LOG(ERROR) << "Please provide path to the device";
    exit(1);
  }

  if (FLAGS_maxpressure < 0) {
    LOG(ERROR) << "Please set max pressure to a non-negative value";
    exit(1);
  }

  std::string dev_path = "/dev/input/" + FLAGS_device;
  int fd = open(dev_path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    PLOG(ERROR) << "Cannot open device: " << dev_path;
    exit(1);
  }

  input_absinfo absinfo;
  if (ioctl(fd, EVIOCGABS(ABS_PRESSURE), &absinfo)) {
    PLOG(ERROR) << "ioctl EVIOCGABS falied";
    exit(1);
  }
  absinfo.maximum = FLAGS_maxpressure;
  if (ioctl(fd, EVIOCSABS(ABS_PRESSURE), &absinfo)) {
    PLOG(ERROR) << "ioctl EVIOCSABS falied";
    exit(1);
  }
  return 0;
}
