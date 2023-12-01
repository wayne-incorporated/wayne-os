// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_UDEV_MOCK_UDEV_DEVICE_H_
#define LIBBRILLO_BRILLO_UDEV_MOCK_UDEV_DEVICE_H_

#include <memory>

#include <brillo/brillo_export.h>
#include <brillo/udev/udev_device.h>
#include <gmock/gmock.h>

namespace brillo {

class BRILLO_EXPORT MockUdevDevice : public UdevDevice {
 public:
  MockUdevDevice() = default;
  MockUdevDevice(const MockUdevDevice&) = delete;
  MockUdevDevice& operator=(const MockUdevDevice&) = delete;

  ~MockUdevDevice() override = default;

  MOCK_METHOD(std::unique_ptr<UdevDevice>, GetParent, (), (const, override));
  MOCK_METHOD(std::unique_ptr<UdevDevice>,
              GetParentWithSubsystemDeviceType,
              (const char*, const char*),
              (const, override));
  MOCK_METHOD(bool, IsInitialized, (), (const, override));
  MOCK_METHOD(uint64_t, GetMicrosecondsSinceInitialized, (), (const, override));
  MOCK_METHOD(uint64_t, GetSequenceNumber, (), (const, override));
  MOCK_METHOD(const char*, GetDevicePath, (), (const, override));
  MOCK_METHOD(const char*, GetDeviceNode, (), (const, override));
  MOCK_METHOD(dev_t, GetDeviceNumber, (), (const, override));
  MOCK_METHOD(const char*, GetDeviceType, (), (const, override));
  MOCK_METHOD(const char*, GetDriver, (), (const, override));
  MOCK_METHOD(const char*, GetSubsystem, (), (const, override));
  MOCK_METHOD(const char*, GetSysPath, (), (const, override));
  MOCK_METHOD(const char*, GetSysName, (), (const, override));
  MOCK_METHOD(const char*, GetSysNumber, (), (const, override));
  MOCK_METHOD(const char*, GetAction, (), (const, override));
  MOCK_METHOD(std::unique_ptr<UdevListEntry>,
              GetDeviceLinksListEntry,
              (),
              (const, override));
  MOCK_METHOD(std::unique_ptr<UdevListEntry>,
              GetPropertiesListEntry,
              (),
              (const, override));
  MOCK_METHOD(const char*, GetPropertyValue, (const char*), (const, override));
  MOCK_METHOD(std::unique_ptr<UdevListEntry>,
              GetTagsListEntry,
              (),
              (const, override));
  MOCK_METHOD(std::unique_ptr<UdevListEntry>,
              GetSysAttributeListEntry,
              (),
              (const, override));
  MOCK_METHOD(const char*,
              GetSysAttributeValue,
              (const char*),
              (const, override));
  MOCK_METHOD(std::unique_ptr<UdevDevice>, Clone, (), (override));
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_UDEV_MOCK_UDEV_DEVICE_H_
