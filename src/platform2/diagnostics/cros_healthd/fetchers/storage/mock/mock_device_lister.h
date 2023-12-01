// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FETCHERS_STORAGE_MOCK_MOCK_DEVICE_LISTER_H_
#define DIAGNOSTICS_CROS_HEALTHD_FETCHERS_STORAGE_MOCK_MOCK_DEVICE_LISTER_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <gmock/gmock.h>

#include "diagnostics/cros_healthd/fetchers/storage/device_lister.h"

namespace diagnostics {

class MockStorageDeviceLister : public StorageDeviceLister {
 public:
  MockStorageDeviceLister() = default;
  MockStorageDeviceLister(const MockStorageDeviceLister&) = delete;
  MockStorageDeviceLister(MockStorageDeviceLister&&) = delete;
  MockStorageDeviceLister& operator=(const MockStorageDeviceLister&) = delete;
  MockStorageDeviceLister& operator=(MockStorageDeviceLister&&) = delete;
  ~MockStorageDeviceLister() override = default;

  MOCK_METHOD(std::vector<std::string>,
              ListDevices,
              (const base::FilePath&),
              (const, override));
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FETCHERS_STORAGE_MOCK_MOCK_DEVICE_LISTER_H_
