// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLCSERVICE_BOOT_MOCK_BOOT_DEVICE_H_
#define DLCSERVICE_BOOT_MOCK_BOOT_DEVICE_H_

#include "dlcservice/boot/boot_device.h"

#include <string>

#include <base/files/file_path.h>

namespace dlcservice {

class MockBootDevice : public BootDeviceInterface {
 public:
  MockBootDevice() = default;
  MockBootDevice(const MockBootDevice&) = delete;
  MockBootDevice& operator=(const MockBootDevice&) = delete;

  MOCK_METHOD(bool, IsRemovableDevice, (const std::string&), (override));
  MOCK_METHOD(base::FilePath, GetBootDevice, (), (override));
};

}  // namespace dlcservice

#endif  // DLCSERVICE_BOOT_MOCK_BOOT_DEVICE_H_
