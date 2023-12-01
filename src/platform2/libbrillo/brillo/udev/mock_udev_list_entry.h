// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_UDEV_MOCK_UDEV_LIST_ENTRY_H_
#define LIBBRILLO_BRILLO_UDEV_MOCK_UDEV_LIST_ENTRY_H_

#include <memory>

#include <brillo/brillo_export.h>
#include <brillo/udev/udev_list_entry.h>
#include <gmock/gmock.h>

namespace brillo {

class BRILLO_EXPORT MockUdevListEntry : public UdevListEntry {
 public:
  MockUdevListEntry() = default;
  MockUdevListEntry(const MockUdevListEntry&) = delete;
  MockUdevListEntry& operator=(const MockUdevListEntry&) = delete;

  ~MockUdevListEntry() override = default;

  MOCK_METHOD(std::unique_ptr<UdevListEntry>, GetNext, (), (const, override));
  MOCK_METHOD(std::unique_ptr<UdevListEntry>,
              GetByName,
              (const char*),
              (const, override));
  MOCK_METHOD(const char*, GetName, (), (const, override));
  MOCK_METHOD(const char*, GetValue, (), (const, override));
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_UDEV_MOCK_UDEV_LIST_ENTRY_H_
