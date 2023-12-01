// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLCSERVICE_BOOT_BOOT_DEVICE_H_
#define DLCSERVICE_BOOT_BOOT_DEVICE_H_

#include <string>

#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include <base/files/file_path.h>

namespace dlcservice {

class BootDeviceInterface {
 public:
  virtual ~BootDeviceInterface() = default;

  // Returns true if the root |device| (e.g., "/dev/sdb") is known to be
  // removable, false otherwise.
  virtual bool IsRemovableDevice(const std::string& device) = 0;

  // Returns the currently booted rootfs partition. "/dev/sda3", for example.
  // Unless `strip_partition` is passed in, in which case it will return the
  // currently booted device path without any partition.
  virtual base::FilePath GetBootDevice() = 0;
};

class BootDevice : public BootDeviceInterface {
 public:
  BootDevice() = default;
  ~BootDevice() override = default;

  BootDevice(const BootDevice&) = delete;
  BootDevice& operator=(const BootDevice&) = delete;

  // BootDeviceInterface overrides:
  bool IsRemovableDevice(const std::string& device) override;
  base::FilePath GetBootDevice() override;

 private:
  FRIEND_TEST(BootDeviceTest, SysfsBlockDeviceTest);
  // Returns the sysfs block device for a root block device. For example,
  // SysfsBlockDevice("/dev/sda") returns "/sys/block/sda". Returns an empty
  // string if the input device is not of the "/dev/xyz" form.
  std::string SysfsBlockDevice(const std::string& device);
};

}  // namespace dlcservice

#endif  // DLCSERVICE_BOOT_BOOT_DEVICE_H_
