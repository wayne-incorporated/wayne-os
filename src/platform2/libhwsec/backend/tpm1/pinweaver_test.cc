// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "libhwsec/backend/tpm1/backend_test_base.h"

using hwsec_foundation::error::testing::IsOkAndHolds;
using hwsec_foundation::error::testing::ReturnError;
using hwsec_foundation::error::testing::ReturnValue;
using testing::_;
using testing::DoAll;
using testing::NiceMock;
using testing::Return;
using testing::SaveArg;
using testing::SetArgPointee;
using tpm_manager::TpmManagerStatus;
namespace hwsec {

using BackendPinweaverTpm1Test = BackendTpm1TestBase;

TEST_F(BackendPinweaverTpm1Test, IsEnabled) {
  EXPECT_THAT(backend_->GetPinWeaverTpm1().IsEnabled(), IsOkAndHolds(false));
}

}  // namespace hwsec
