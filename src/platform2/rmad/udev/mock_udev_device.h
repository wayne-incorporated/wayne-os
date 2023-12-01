// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UDEV_MOCK_UDEV_DEVICE_H_
#define RMAD_UDEV_MOCK_UDEV_DEVICE_H_

#include "rmad/udev/udev_device.h"

#include <memory>
#include <string>

namespace rmad {

class MockUdevDevice : public UdevDevice {
 public:
  MockUdevDevice() = default;
  MockUdevDevice(const MockUdevDevice&) = delete;
  MockUdevDevice& operator=(const MockUdevDevice&) = delete;

  ~MockUdevDevice() override = default;

  MOCK_METHOD(bool, IsRemovable, (), (const, override));
  MOCK_METHOD(std::string, GetSysPath, (), (const, override));
  MOCK_METHOD(std::string, GetDeviceNode, (), (const, override));
  MOCK_METHOD(std::string, GetFileSystemType, (), (override));
};

}  // namespace rmad

#endif  // RMAD_UDEV_MOCK_UDEV_DEVICE_H_
