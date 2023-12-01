// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>
#include <trunks/mock_tpm_utility.h>

#include "libhwsec/backend/tpm2/backend_test_base.h"

using hwsec_foundation::error::testing::IsOkAndHolds;
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

using BackendRandomTpm2Test = BackendTpm2TestBase;

TEST_F(BackendRandomTpm2Test, RandomBlob) {
  const size_t kFakeSize = 42;
  const brillo::Blob kFakeData(kFakeSize, 'X');

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              GenerateRandom(kFakeSize, nullptr, _))
      .WillOnce(DoAll(SetArgPointee<2>(brillo::BlobToString(kFakeData)),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_THAT(backend_->GetRandomTpm2().RandomBlob(kFakeSize),
              IsOkAndHolds(kFakeData));
}

TEST_F(BackendRandomTpm2Test, RandomSecureBlob) {
  const size_t kFakeSize = 42;
  const brillo::SecureBlob kFakeData(kFakeSize, 'X');

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              GenerateRandom(kFakeSize, nullptr, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeData.to_string()),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_THAT(backend_->GetRandomTpm2().RandomSecureBlob(kFakeSize),
              IsOkAndHolds(kFakeData));
}

TEST_F(BackendRandomTpm2Test, RandomSecureBlobWrongSize) {
  const size_t kFakeSize = 42;
  const brillo::SecureBlob kFakeData(kFakeSize - 10, 'X');

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              GenerateRandom(kFakeSize, nullptr, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeData.to_string()),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_THAT(backend_->GetRandomTpm2().RandomSecureBlob(kFakeSize), NotOk());
}

}  // namespace hwsec
