// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_UDEV_MOCK_UDEV_H_
#define LIBBRILLO_BRILLO_UDEV_MOCK_UDEV_H_

#include <memory>

#include <brillo/brillo_export.h>
#include <brillo/udev/udev.h>
#include <brillo/udev/udev_device.h>
#include <brillo/udev/udev_enumerate.h>
#include <brillo/udev/udev_monitor.h>
#include <gmock/gmock.h>

namespace brillo {

class BRILLO_EXPORT MockUdev : public Udev {
 public:
  MockUdev() : Udev(nullptr) {}
  MockUdev(const MockUdev&) = delete;
  MockUdev& operator=(const MockUdev&) = delete;

  ~MockUdev() override = default;

  MOCK_METHOD(std::unique_ptr<UdevDevice>,
              CreateDeviceFromSysPath,
              (const char*),
              (override));
  MOCK_METHOD(std::unique_ptr<UdevDevice>,
              CreateDeviceFromDeviceNumber,
              (char, dev_t),
              (override));
  MOCK_METHOD(std::unique_ptr<UdevDevice>,
              CreateDeviceFromSubsystemSysName,
              (const char*, const char*),
              (override));
  MOCK_METHOD(std::unique_ptr<UdevEnumerate>, CreateEnumerate, (), (override));
  MOCK_METHOD(std::unique_ptr<UdevMonitor>,
              CreateMonitorFromNetlink,
              (const char*),
              (override));
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_UDEV_MOCK_UDEV_H_
