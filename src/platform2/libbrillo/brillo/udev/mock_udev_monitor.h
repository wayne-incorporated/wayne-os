// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_UDEV_MOCK_UDEV_MONITOR_H_
#define LIBBRILLO_BRILLO_UDEV_MOCK_UDEV_MONITOR_H_

#include <memory>

#include <brillo/brillo_export.h>
#include <brillo/udev/udev_monitor.h>
#include <gmock/gmock.h>

namespace brillo {

class BRILLO_EXPORT MockUdevMonitor : public UdevMonitor {
 public:
  MockUdevMonitor() = default;
  MockUdevMonitor(const MockUdevMonitor&) = delete;
  MockUdevMonitor& operator=(const MockUdevMonitor&) = delete;

  ~MockUdevMonitor() override = default;

  MOCK_METHOD(bool, EnableReceiving, (), (override));
  MOCK_METHOD(int, GetFileDescriptor, (), (const, override));
  MOCK_METHOD(std::unique_ptr<UdevDevice>, ReceiveDevice, (), (override));
  MOCK_METHOD(bool,
              FilterAddMatchSubsystemDeviceType,
              (const char*, const char*),
              (override));
  MOCK_METHOD(bool, FilterAddMatchTag, (const char*), (override));
  MOCK_METHOD(bool, FilterUpdate, (), (override));
  MOCK_METHOD(bool, FilterRemove, (), (override));
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_UDEV_MOCK_UDEV_MONITOR_H_
