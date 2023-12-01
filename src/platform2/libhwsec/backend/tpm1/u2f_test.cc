// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "libhwsec/backend/tpm1/backend_test_base.h"

using hwsec_foundation::error::testing::IsOkAndHolds;

namespace hwsec {

using BackendU2fTpm1Test = BackendTpm1TestBase;

TEST_F(BackendU2fTpm1Test, IsEnabled) {
  EXPECT_THAT(backend_->GetU2fTpm1().IsEnabled(), IsOkAndHolds(false));
}

}  // namespace hwsec
