// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FEDERATED_MOCK_STORAGE_MANAGER_H_
#define FEDERATED_MOCK_STORAGE_MANAGER_H_

#include "federated/storage_manager.h"

#include <optional>
#include <string>

#include <gmock/gmock.h>

namespace federated {

class MockStorageManager : public StorageManager {
 public:
  MockStorageManager() = default;
  MockStorageManager(const MockStorageManager&) = delete;
  MockStorageManager& operator=(const MockStorageManager&) = delete;

  ~MockStorageManager() override = default;

  MOCK_METHOD(void, InitializeSessionManagerProxy, (dbus::Bus*), (override));
  MOCK_METHOD(bool,
              OnExampleReceived,
              (const std::string&, const std::string&),
              (override));
  MOCK_METHOD(std::optional<ExampleDatabase::Iterator>,
              GetExampleIterator,
              (const std::string&,
               const std::string&,
               const fcp::client::CrosExampleSelectorCriteria&),
              (const, override));
};

}  // namespace federated

#endif  // FEDERATED_MOCK_STORAGE_MANAGER_H_
