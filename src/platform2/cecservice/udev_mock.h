// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CECSERVICE_UDEV_MOCK_H_
#define CECSERVICE_UDEV_MOCK_H_

#include <memory>
#include <vector>

#include <gmock/gmock.h>

#include "cecservice/udev.h"

namespace cecservice {

class UdevMock : public Udev {
 public:
  UdevMock() = default;
  UdevMock(const UdevMock&) = delete;
  UdevMock& operator=(const UdevMock&) = delete;

  MOCK_CONST_METHOD1(EnumerateDevices, bool(std::vector<base::FilePath>*));
};

class UdevFactoryMock : public UdevFactory {
 public:
  UdevFactoryMock() = default;
  UdevFactoryMock(const UdevFactoryMock&) = delete;
  UdevFactoryMock& operator=(const UdevFactoryMock&) = delete;

  MOCK_CONST_METHOD2(Create,
                     std::unique_ptr<Udev>(
                         const Udev::DeviceCallback& device_added_callback,
                         const Udev::DeviceCallback& device_removed_callback));
};

}  // namespace cecservice

#endif  // CECSERVICE_UDEV_MOCK_H_
