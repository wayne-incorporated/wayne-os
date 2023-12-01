// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_TEST_UTILS_FAKE_TPM_NVRAM_FOR_TEST_H_
#define LIBHWSEC_TEST_UTILS_FAKE_TPM_NVRAM_FOR_TEST_H_

#include <memory>
#include <string>
#include <vector>

#include <absl/container/flat_hash_map.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libhwsec/hwsec_export.h"

// Forward declarations
namespace org::chromium {
class TpmNvramProxyMock;
}  // namespace org::chromium

namespace hwsec {

// A fake TPM nvram implementation for testing.

class HWSEC_EXPORT FakeTpmNvramForTest {
 public:
  FakeTpmNvramForTest();
  ~FakeTpmNvramForTest();

  // Initialize the fake nvram. Returns true on success.
  virtual bool Init();

  // Define a platform create space.
  bool DefinePlatformCreateSpace(uint32_t index, uint32_t size);

  testing::NiceMock<org::chromium::TpmNvramProxyMock>* GetMock();

 private:
  struct SpaceInfo;

  std::unique_ptr<testing::NiceMock<org::chromium::TpmNvramProxyMock>>
      tpm_nvram_;
  absl::flat_hash_map<uint32_t, SpaceInfo> space_info_;
  std::string owner_auth_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_TEST_UTILS_FAKE_TPM_NVRAM_FOR_TEST_H_
