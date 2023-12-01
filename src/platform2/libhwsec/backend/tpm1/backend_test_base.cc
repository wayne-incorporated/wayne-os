// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/tpm1/backend_test_base.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include <absl/base/attributes.h>
#include <brillo/secure_blob.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>
#include <tpm_manager-client-test/tpm_manager/dbus-proxy-mocks.h>

#include "libhwsec/backend/tpm1/backend.h"
#include "libhwsec/error/tpm1_error.h"
#include "libhwsec/middleware/middleware_derivative.h"
#include "libhwsec/middleware/middleware_owner.h"
#include "libhwsec/overalls/mock_overalls.h"
#include "libhwsec/proxy/proxy_for_test.h"
#include "libhwsec/status.h"

using hwsec_foundation::error::testing::IsOkAndHolds;
using testing::_;
using testing::Args;
using testing::AtMost;
using testing::DoAll;
using testing::ElementsAreArray;
using testing::Return;
using testing::SetArgPointee;
using tpm_manager::TpmManagerStatus;

namespace hwsec {

namespace {

// TSS UUID matcher.
MATCHER_P(MatchTssUUID, uuid, "") {
  return arg.ulTimeLow == uuid.ulTimeLow && arg.usTimeMid == uuid.usTimeMid &&
         arg.usTimeHigh == uuid.usTimeHigh &&
         arg.bClockSeqHigh == uuid.bClockSeqHigh &&
         arg.bClockSeqLow == uuid.bClockSeqLow &&
         arg.rgbNode[0] == uuid.rgbNode[0] &&
         arg.rgbNode[1] == uuid.rgbNode[1] &&
         arg.rgbNode[2] == uuid.rgbNode[2] &&
         arg.rgbNode[3] == uuid.rgbNode[3] &&
         arg.rgbNode[4] == uuid.rgbNode[4] && arg.rgbNode[5] == uuid.rgbNode[5];
}

}  // namespace

BackendTpm1TestBase::BackendTpm1TestBase() = default;
BackendTpm1TestBase::~BackendTpm1TestBase() = default;

void BackendTpm1TestBase::SetUp() {
  proxy_ = std::make_unique<ProxyForTest>();

  auto backend = std::make_unique<BackendTpm1>(*proxy_, MiddlewareDerivative{});
  backend_ = backend.get();

  middleware_owner_ = std::make_unique<MiddlewareOwner>(
      std::move(backend), ThreadingMode::kCurrentThread);

  backend_->set_middleware_derivative_for_test(middleware_owner_->Derive());

  EXPECT_CALL(proxy_->GetMockOveralls(), Ospi_Context_Create(_))
      .WillRepeatedly(
          DoAll(SetArgPointee<0>(kDefaultContext), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Context_Connect(kDefaultContext, nullptr))
      .WillRepeatedly(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Context_GetTpmObject(kDefaultContext, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(kDefaultTpm), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(), Ospi_Context_Close(kDefaultContext))
      .WillRepeatedly(Return(TPM_SUCCESS));
}

void BackendTpm1TestBase::SetupSrk() {
  const uint32_t kFakeSrkAuthUsage = 0x9876123;
  const uint32_t kFakeSrkUsagePolicy = 0x1283789;
  TSS_UUID SRK_UUID = TSS_UUID_SRK;

  tpm_manager::GetTpmNonsensitiveStatusReply reply;
  reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
  reply.set_is_owned(true);
  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(),
              GetTpmNonsensitiveStatus(_, _, _, _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(reply), Return(true)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Context_LoadKeyByUUID(kDefaultContext, TSS_PS_TYPE_SYSTEM,
                                         MatchTssUUID(SRK_UUID), _))
      .WillRepeatedly(
          DoAll(SetArgPointee<3>(kDefaultSrkHandle), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_GetAttribUint32(kDefaultSrkHandle, TSS_TSPATTRIB_KEY_INFO,
                                   TSS_TSPATTRIB_KEYINFO_AUTHUSAGE, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<3>(kFakeSrkAuthUsage), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_GetPolicyObject(kDefaultSrkHandle, TSS_POLICY_USAGE, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(kFakeSrkUsagePolicy), Return(TPM_SUCCESS)));

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Policy_SetSecret(kFakeSrkUsagePolicy, TSS_SECRET_MODE_PLAIN, _, _))
      .WillRepeatedly(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Key_GetPubKey(kDefaultSrkHandle, _, _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(kDefaultSrkPubkey.size()),
                            SetArgPointee<2>(kDefaultSrkPubkey.data()),
                            Return(TPM_SUCCESS)));
}

void BackendTpm1TestBase::SetupDelegate() {
  // Cache the default user TPM handle.
  EXPECT_THAT(backend_->GetTssHelper().GetUserTpmHandle(),
              IsOkAndHolds(kDefaultTpm));

  TSS_HPOLICY kPolicy1 = 0x9909;

  std::string fake_delegate_blob = "fake_deleagte_blob";
  std::string fake_delegate_secret = "fake_deleagte_secret";

  tpm_manager::GetTpmStatusReply reply;
  reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
  *reply.mutable_local_data()->mutable_owner_delegate()->mutable_blob() =
      fake_delegate_blob;
  *reply.mutable_local_data()->mutable_owner_delegate()->mutable_secret() =
      fake_delegate_secret;
  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(), GetTpmStatus(_, _, _, _))
      .Times(AtMost(1))
      .WillOnce(DoAll(SetArgPointee<1>(reply), Return(true)))
      .RetiresOnSaturation();

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Context_GetTpmObject(kDefaultContext, _))
      .Times(AtMost(1))
      .WillOnce(
          DoAll(SetArgPointee<1>(kDefaultDelegateTpm), Return(TPM_SUCCESS)))
      .RetiresOnSaturation();

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_GetPolicyObject(kDefaultDelegateTpm, TSS_POLICY_USAGE, _))
      .WillRepeatedly(DoAll(SetArgPointee<2>(kPolicy1), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Policy_SetSecret(kPolicy1, TSS_SECRET_MODE_PLAIN, _, _))
      .With(Args<3, 2>(ElementsAreArray(fake_delegate_secret)))
      .WillRepeatedly(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_SetAttribData(kPolicy1, TSS_TSPATTRIB_POLICY_DELEGATION_INFO,
                                 TSS_TSPATTRIB_POLDEL_OWNERBLOB, _, _))
      .With(Args<4, 3>(ElementsAreArray(fake_delegate_blob)))
      .WillRepeatedly(Return(TPM_SUCCESS));
}

}  // namespace hwsec
