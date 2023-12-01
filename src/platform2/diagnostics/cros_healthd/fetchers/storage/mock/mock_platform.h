// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FETCHERS_STORAGE_MOCK_MOCK_PLATFORM_H_
#define DIAGNOSTICS_CROS_HEALTHD_FETCHERS_STORAGE_MOCK_MOCK_PLATFORM_H_

#include <cstdint>
#include <string>

#include <base/files/file_path.h>
#include <base/types/expected.h>
#include <gmock/gmock.h>

#include "diagnostics/cros_healthd/fetchers/storage/platform.h"

namespace diagnostics {

class MockPlatform : public Platform {
 public:
  MockPlatform() = default;
  MockPlatform(const MockPlatform&) = delete;
  MockPlatform(MockPlatform&&) = delete;
  MockPlatform& operator=(const MockPlatform&) = delete;
  MockPlatform& operator=(MockPlatform&&) = delete;
  ~MockPlatform() override = default;

  MOCK_METHOD(std::string, GetRootDeviceName, (), (const, override));
  MOCK_METHOD(
      (base::expected<uint64_t, ash::cros_healthd::mojom::ProbeErrorPtr>),
      GetDeviceSizeBytes,
      (const base::FilePath&),
      (const, override));
  MOCK_METHOD(
      (base::expected<uint64_t, ash::cros_healthd::mojom::ProbeErrorPtr>),
      GetDeviceBlockSizeBytes,
      (const base::FilePath&),
      (const, override));
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FETCHERS_STORAGE_MOCK_MOCK_PLATFORM_H_
