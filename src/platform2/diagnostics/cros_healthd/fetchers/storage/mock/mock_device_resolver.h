
// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FETCHERS_STORAGE_MOCK_MOCK_DEVICE_RESOLVER_H_
#define DIAGNOSTICS_CROS_HEALTHD_FETCHERS_STORAGE_MOCK_MOCK_DEVICE_RESOLVER_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <gmock/gmock.h>

#include "diagnostics/cros_healthd/fetchers/storage/device_resolver.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

class MockStorageDeviceResolver : public StorageDeviceResolver {
 public:
  MockStorageDeviceResolver() = default;
  MockStorageDeviceResolver(const MockStorageDeviceResolver&) = delete;
  MockStorageDeviceResolver(MockStorageDeviceResolver&&) = delete;
  MockStorageDeviceResolver& operator=(const MockStorageDeviceResolver&) =
      delete;
  MockStorageDeviceResolver& operator=(MockStorageDeviceResolver&&) = delete;
  ~MockStorageDeviceResolver() override = default;

  MOCK_METHOD(ash::cros_healthd::mojom::StorageDevicePurpose,
              GetDevicePurpose,
              (const std::string&),
              (const, override));
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FETCHERS_STORAGE_MOCK_MOCK_DEVICE_RESOLVER_H_
