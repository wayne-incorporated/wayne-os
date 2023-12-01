// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM2_BACKEND_TEST_BASE_H_
#define LIBHWSEC_BACKEND_TPM2_BACKEND_TEST_BASE_H_

#include <memory>

#include <gtest/gtest.h>

#include "libhwsec/backend/tpm2/backend.h"
#include "libhwsec/middleware/middleware_owner.h"
#include "libhwsec/proxy/proxy_for_test.h"

namespace hwsec {

class BackendTpm2TestBase : public ::testing::Test {
 public:
  BackendTpm2TestBase();
  BackendTpm2TestBase(const BackendTpm2TestBase&) = delete;
  BackendTpm2TestBase& operator=(const BackendTpm2TestBase&) = delete;
  ~BackendTpm2TestBase() override;

  void SetUp() override;

 protected:
  std::unique_ptr<ProxyForTest> proxy_;
  std::unique_ptr<MiddlewareOwner> middleware_owner_;
  BackendTpm2* backend_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM2_BACKEND_TEST_BASE_H_
