// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM1_BACKEND_TEST_BASE_H_
#define LIBHWSEC_BACKEND_TPM1_BACKEND_TEST_BASE_H_

#include <memory>
#include <utility>

#include <absl/base/attributes.h>
#include <brillo/secure_blob.h>
#include <gtest/gtest.h>

#include "libhwsec/backend/tpm1/backend.h"
#include "libhwsec/middleware/middleware_derivative.h"
#include "libhwsec/proxy/proxy_for_test.h"

namespace hwsec {

class BackendTpm1TestBase : public ::testing::Test {
 public:
  BackendTpm1TestBase();
  BackendTpm1TestBase(const BackendTpm1TestBase&) = delete;
  BackendTpm1TestBase& operator=(const BackendTpm1TestBase&) = delete;
  ~BackendTpm1TestBase() override;

  void SetUp() override;

 protected:
  static inline constexpr TSS_HCONTEXT kDefaultContext = 9876;
  static inline constexpr TSS_HTPM kDefaultTpm = 6543;
  static inline constexpr TSS_HTPM kDefaultDelegateTpm = 9527;
  static inline constexpr uint32_t kDefaultSrkHandle = 5566123;

  void SetupSrk();
  void SetupDelegate();

  brillo::Blob kDefaultSrkPubkey = brillo::BlobFromString("default_srk");
  std::unique_ptr<ProxyForTest> proxy_;
  std::unique_ptr<MiddlewareOwner> middleware_owner_;
  BackendTpm1* backend_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM1_BACKEND_TEST_BASE_H_
