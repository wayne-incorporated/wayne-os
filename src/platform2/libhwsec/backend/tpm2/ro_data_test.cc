// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <memory>
#include <utility>

#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>
#include <tpm_manager-client-test/tpm_manager/dbus-proxy-mocks.h>

#include "libhwsec/backend/tpm2/backend_test_base.h"

using hwsec_foundation::error::testing::IsOkAndHolds;
using hwsec_foundation::error::testing::NotOk;
using testing::_;
using testing::DoAll;
using testing::Return;
using testing::SetArgPointee;
using tpm_manager::NvramResult;
using tpm_manager::NvramSpaceAttribute;

namespace hwsec {

using BackendRoDataTpm2Test = BackendTpm2TestBase;

TEST_F(BackendRoDataTpm2Test, IsReady) {
  tpm_manager::GetSpaceInfoReply info_reply;
  info_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  info_reply.set_size(315);
  info_reply.set_is_read_locked(false);
  info_reply.set_is_write_locked(false);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_PERSISTENT_WRITE_LOCK);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_READ_AUTHORIZATION);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), GetSpaceInfo(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(info_reply), Return(true)));

  EXPECT_THAT(backend_->GetRoDataTpm2().IsReady(RoSpace::kG2fCert),
              IsOkAndHolds(true));
}

TEST_F(BackendRoDataTpm2Test, IsReadyNotAvailable) {
  tpm_manager::GetSpaceInfoReply info_reply;
  info_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  info_reply.set_size(315);
  info_reply.set_is_read_locked(false);
  info_reply.set_is_write_locked(false);
  // Missing required attributes.
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), GetSpaceInfo(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(info_reply), Return(true)));

  EXPECT_THAT(backend_->GetRoDataTpm2().IsReady(RoSpace::kG2fCert),
              IsOkAndHolds(false));
}

TEST_F(BackendRoDataTpm2Test, IsReadySpaceNotExist) {
  tpm_manager::GetSpaceInfoReply info_reply;
  info_reply.set_result(NvramResult::NVRAM_RESULT_SPACE_DOES_NOT_EXIST);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), GetSpaceInfo(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(info_reply), Return(true)));

  EXPECT_THAT(backend_->GetRoDataTpm2().IsReady(RoSpace::kG2fCert),
              IsOkAndHolds(false));
}

TEST_F(BackendRoDataTpm2Test, IsReadyOtherError) {
  tpm_manager::GetSpaceInfoReply info_reply;
  info_reply.set_result(NvramResult::NVRAM_RESULT_DEVICE_ERROR);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), GetSpaceInfo(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(info_reply), Return(true)));

  EXPECT_THAT(backend_->GetRoDataTpm2().IsReady(RoSpace::kG2fCert), NotOk());
}

TEST_F(BackendRoDataTpm2Test, Read) {
  const std::string kFakeData = "fake_data";

  tpm_manager::ReadSpaceReply read_reply;
  read_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  read_reply.set_data(kFakeData);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), ReadSpace(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(read_reply), Return(true)));

  EXPECT_THAT(backend_->GetRoDataTpm2().Read(RoSpace::kG2fCert),
              IsOkAndHolds(brillo::BlobFromString(kFakeData)));
}

}  // namespace hwsec
