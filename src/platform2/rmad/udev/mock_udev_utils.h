// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UDEV_MOCK_UDEV_UTILS_H_
#define RMAD_UDEV_MOCK_UDEV_UTILS_H_

#include "rmad/udev/udev_utils.h"

#include <memory>
#include <string>
#include <vector>

namespace rmad {

class MockUdevUtils : public UdevUtils {
 public:
  MockUdevUtils() = default;
  MockUdevUtils(const MockUdevUtils&) = delete;
  MockUdevUtils& operator=(const MockUdevUtils&) = delete;

  ~MockUdevUtils() override = default;

  MOCK_METHOD(std::vector<std::unique_ptr<UdevDevice>>,
              EnumerateBlockDevices,
              (),
              (override));
  MOCK_METHOD(bool,
              GetBlockDeviceFromDevicePath,
              (const std::string&, std::unique_ptr<UdevDevice>*),
              (override));
};

}  // namespace rmad

#endif  // RMAD_UDEV_MOCK_UDEV_UTILS_H_
