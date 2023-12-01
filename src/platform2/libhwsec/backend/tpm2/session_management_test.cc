// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>
#include <trunks/mock_hmac_session.h>

#include "libhwsec/backend/tpm2/backend_test_base.h"
#include "libhwsec/backend/tpm2/session_management.h"

using hwsec_foundation::error::testing::IsOk;
using hwsec_foundation::error::testing::NotOk;
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

using BackendSessionManagementTpm2Test = BackendTpm2TestBase;

TEST_F(BackendSessionManagementTpm2Test, GetOrCreateHmacSession) {
  EXPECT_CALL(proxy_->GetMockHmacSession(), StartUnboundSession(false, false))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  auto result0 = backend_->GetSessionManagementTpm2().GetOrCreateHmacSession(
      SessionSecuritySetting::kNoEncrypted);
  EXPECT_THAT(result0, IsOk());

  // Check the cache work.
  auto result1 = backend_->GetSessionManagementTpm2().GetOrCreateHmacSession(
      SessionSecuritySetting::kNoEncrypted);
  EXPECT_THAT(result1, IsOk());
}

TEST_F(BackendSessionManagementTpm2Test, GetOrCreateHmacSessionAndFlush) {
  // Nothing to flush.
  auto result0 = backend_->GetSessionManagementTpm2().FlushInvalidSessions();
  EXPECT_THAT(result0, NotOk());

  EXPECT_CALL(proxy_->GetMockHmacSession(), StartUnboundSession(false, true))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  EXPECT_CALL(proxy_->GetMockHmacSession(), StartUnboundSession(true, true))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  auto result1 = backend_->GetSessionManagementTpm2().GetOrCreateHmacSession(
      SessionSecuritySetting::kEncrypted);
  EXPECT_THAT(result1, IsOk());

  // Check the cache work.
  auto result2 = backend_->GetSessionManagementTpm2().GetOrCreateHmacSession(
      SessionSecuritySetting::kEncrypted);
  EXPECT_THAT(result2, IsOk());

  auto result3 = backend_->GetSessionManagementTpm2().GetOrCreateHmacSession(
      SessionSecuritySetting::kSaltAndEncrypted);
  EXPECT_THAT(result3, IsOk());

  // Check the cache work.
  auto result4 = backend_->GetSessionManagementTpm2().GetOrCreateHmacSession(
      SessionSecuritySetting::kSaltAndEncrypted);
  EXPECT_THAT(result4, IsOk());

  // Flush again.
  auto result5 = backend_->GetSessionManagementTpm2().FlushInvalidSessions();
  EXPECT_THAT(result5, IsOk());

  // The cache should not work.
  EXPECT_CALL(proxy_->GetMockHmacSession(), StartUnboundSession(false, true))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  auto result6 = backend_->GetSessionManagementTpm2().GetOrCreateHmacSession(
      SessionSecuritySetting::kEncrypted);
  EXPECT_THAT(result6, IsOk());
}

}  // namespace hwsec
