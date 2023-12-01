// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_UDEV_MOCK_UDEV_ENUMERATE_H_
#define LIBBRILLO_BRILLO_UDEV_MOCK_UDEV_ENUMERATE_H_

#include <memory>

#include <brillo/brillo_export.h>
#include <brillo/udev/udev_enumerate.h>
#include <gmock/gmock.h>

namespace brillo {

class BRILLO_EXPORT MockUdevEnumerate : public UdevEnumerate {
 public:
  MockUdevEnumerate() = default;
  MockUdevEnumerate(const MockUdevEnumerate&) = delete;
  MockUdevEnumerate& operator=(const MockUdevEnumerate&) = delete;

  ~MockUdevEnumerate() override = default;

  MOCK_METHOD(bool, AddMatchSubsystem, (const char*), (override));
  MOCK_METHOD(bool, AddNoMatchSubsystem, (const char*), (override));
  MOCK_METHOD(bool,
              AddMatchSysAttribute,
              (const char*, const char*),
              (override));
  MOCK_METHOD(bool,
              AddNoMatchSysAttribute,
              (const char*, const char*),
              (override));
  MOCK_METHOD(bool, AddMatchProperty, (const char*, const char*), (override));
  MOCK_METHOD(bool, AddMatchSysName, (const char*), (override));
  MOCK_METHOD(bool, AddMatchTag, (const char*), (override));
  MOCK_METHOD(bool, AddMatchIsInitialized, (), (override));
  MOCK_METHOD(bool, AddSysPath, (const char*), (override));
  MOCK_METHOD(bool, ScanDevices, (), (override));
  MOCK_METHOD(bool, ScanSubsystems, (), (override));
  MOCK_METHOD(std::unique_ptr<UdevListEntry>,
              GetListEntry,
              (),
              (const, override));
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_UDEV_MOCK_UDEV_ENUMERATE_H_
