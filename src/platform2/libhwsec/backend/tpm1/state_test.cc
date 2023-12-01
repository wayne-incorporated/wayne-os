// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <base/test/task_environment.h>
#include <base/test/test_future.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>
#include <tpm_manager-client-test/tpm_manager/dbus-proxy-mocks.h>

#include "libhwsec/backend/tpm1/backend_test_base.h"

using base::test::TestFuture;
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

class BackendStateTpm1Test : public BackendTpm1TestBase {
 protected:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY,
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
};

TEST_F(BackendStateTpm1Test, IsEnabled) {
  tpm_manager::GetTpmNonsensitiveStatusReply reply;
  reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
  reply.set_is_enabled(true);
  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(),
              GetTpmNonsensitiveStatus(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(reply), Return(true)));

  EXPECT_THAT(backend_->GetStateTpm1().IsEnabled(), IsOkAndHolds(true));
}

TEST_F(BackendStateTpm1Test, IsReady) {
  tpm_manager::GetTpmNonsensitiveStatusReply reply;
  reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
  reply.set_is_owned(true);
  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(),
              GetTpmNonsensitiveStatus(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(reply), Return(true)));

  EXPECT_THAT(backend_->GetStateTpm1().IsReady(), IsOkAndHolds(true));
}

TEST_F(BackendStateTpm1Test, Prepare) {
  tpm_manager::TakeOwnershipReply reply;
  reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(), TakeOwnership(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(reply), Return(true)));

  EXPECT_THAT(backend_->GetStateTpm1().Prepare(), IsOk());
}

TEST_F(BackendStateTpm1Test, WaitUntilReadyEarly) {
  tpm_manager::GetTpmNonsensitiveStatusReply reply;
  reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
  reply.set_is_enabled(true);
  reply.set_is_owned(true);
  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(),
              GetTpmNonsensitiveStatus(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(reply), Return(true)));

  TestFuture<Status> future;
  backend_->GetStateTpm1().WaitUntilReady(future.GetCallback<Status>());

  EXPECT_THAT(future.Get(), IsOk());
}

TEST_F(BackendStateTpm1Test, WaitUntilReadySignal) {
  tpm_manager::GetTpmNonsensitiveStatusReply reply;
  reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
  reply.set_is_enabled(false);
  reply.set_is_owned(false);
  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(),
              GetTpmNonsensitiveStatus(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(reply), Return(true)));

  base::RepeatingCallback<void(const tpm_manager::OwnershipTakenSignal&)>
      signal_callback = base::NullCallback();

  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(),
              DoRegisterSignalOwnershipTakenSignalHandler(_, _))
      .WillOnce(SaveArg<0>(&signal_callback));

  TestFuture<Status> future;
  backend_->GetStateTpm1().WaitUntilReady(future.GetCallback<Status>());

  task_environment_.RunUntilIdle();
  ASSERT_NE(signal_callback, base::NullCallback());

  // Trigger the signal.
  signal_callback.Run(tpm_manager::OwnershipTakenSignal());

  EXPECT_THAT(future.Get(), IsOk());
}

TEST_F(BackendStateTpm1Test, WaitUntilReadyEarlyAndSignal) {
  tpm_manager::GetTpmNonsensitiveStatusReply reply;
  reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
  reply.set_is_enabled(true);
  reply.set_is_owned(true);
  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(),
              GetTpmNonsensitiveStatus(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(reply), Return(true)));

  base::RepeatingCallback<void(const tpm_manager::OwnershipTakenSignal&)>
      signal_callback = base::NullCallback();

  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(),
              DoRegisterSignalOwnershipTakenSignalHandler(_, _))
      .WillOnce(SaveArg<0>(&signal_callback));

  TestFuture<Status> future;
  backend_->GetStateTpm1().WaitUntilReady(future.GetCallback<Status>());

  EXPECT_THAT(future.Get(), IsOk());

  // Trigger the signal and no crash.
  signal_callback.Run(tpm_manager::OwnershipTakenSignal());
}

}  // namespace hwsec
