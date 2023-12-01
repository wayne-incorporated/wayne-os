// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/rule_test.h"

namespace permission_broker {

RuleTest::RuleTest() : udev_(udev_new()) {}

RuleTest::~RuleTest() = default;

ScopedUdevDevicePtr RuleTest::FindDevice(const std::string& path) {
  ScopedUdevEnumeratePtr enumerate(udev_enumerate_new(udev_.get()));
  udev_enumerate_scan_devices(enumerate.get());

  struct udev_list_entry* entry = nullptr;
  udev_list_entry_foreach(entry,
                          udev_enumerate_get_list_entry(enumerate.get())) {
    const char* syspath = udev_list_entry_get_name(entry);
    ScopedUdevDevicePtr device(
        udev_device_new_from_syspath(udev_.get(), syspath));

    const char* devnode = udev_device_get_devnode(device.get());
    if (devnode && !strcmp(devnode, path.c_str()))
      return device;
  }

  ADD_FAILURE() << "Device '" << path << "' not found.";
  return nullptr;
}

}  // namespace permission_broker
