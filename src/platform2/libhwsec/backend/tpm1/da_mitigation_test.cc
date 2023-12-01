// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <base/time/time.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>
#include <tpm_manager-client-test/tpm_manager/dbus-proxy-mocks.h>

#include "libhwsec/backend/tpm1/backend_test_base.h"

using hwsec_foundation::error::testing::IsOk;
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

using BackendDAMitigationTpm1Test = BackendTpm1TestBase;

TEST_F(BackendDAMitigationTpm1Test, IsReady) {
  tpm_manager::GetTpmNonsensitiveStatusReply reply;
  reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
  reply.set_is_enabled(true);
  reply.set_is_owned(true);
  reply.set_has_reset_lock_permissions(true);
  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(),
              GetTpmNonsensitiveStatus(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(reply), Return(true)));

  EXPECT_THAT(backend_->GetDAMitigationTpm1().IsReady(), IsOkAndHolds(true));
}

TEST_F(BackendDAMitigationTpm1Test, IsNotReady) {
  tpm_manager::GetTpmNonsensitiveStatusReply reply;
  reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
  reply.set_is_enabled(true);
  reply.set_is_owned(true);
  reply.set_has_reset_lock_permissions(false);
  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(),
              GetTpmNonsensitiveStatus(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(reply), Return(true)));

  EXPECT_THAT(backend_->GetDAMitigationTpm1().IsReady(), IsOkAndHolds(false));
}

TEST_F(BackendDAMitigationTpm1Test, GetStatus) {
  const base::TimeDelta kRemaining = base::Minutes(2);

  tpm_manager::GetDictionaryAttackInfoReply reply;
  reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
  reply.set_dictionary_attack_lockout_in_effect(true);
  reply.set_dictionary_attack_lockout_seconds_remaining(kRemaining.InSeconds());
  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(),
              GetDictionaryAttackInfo(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(reply), Return(true)));

  auto result = backend_->GetDAMitigationTpm1().GetStatus();
  ASSERT_OK(result);
  EXPECT_TRUE(result->lockout);
  EXPECT_EQ(result->remaining, kRemaining);
}

TEST_F(BackendDAMitigationTpm1Test, Mitigate) {
  tpm_manager::ResetDictionaryAttackLockReply reply;
  reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(),
              ResetDictionaryAttackLock(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(reply), Return(true)));

  EXPECT_THAT(backend_->GetDAMitigationTpm1().Mitigate(), IsOk());
}

}  // namespace hwsec
