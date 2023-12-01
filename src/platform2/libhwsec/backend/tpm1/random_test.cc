// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "libhwsec/backend/tpm1/backend_test_base.h"
#include "libhwsec/overalls/mock_overalls.h"

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

using BackendRandomTpm1Test = BackendTpm1TestBase;

TEST_F(BackendRandomTpm1Test, RandomBlob) {
  const size_t kFakeSize = 42;
  const brillo::Blob kFakeData(kFakeSize, 'X');

  brillo::Blob fake_data = kFakeData;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_TPM_GetRandom(kDefaultTpm, kFakeSize, _))
      .WillOnce(DoAll(SetArgPointee<2>(fake_data.data()), Return(TPM_SUCCESS)));

  EXPECT_THAT(backend_->GetRandomTpm1().RandomBlob(kFakeSize),
              IsOkAndHolds(kFakeData));
}

TEST_F(BackendRandomTpm1Test, RandomSecureBlob) {
  const size_t kFakeSize = 42;
  const brillo::SecureBlob kFakeData(kFakeSize, 'Y');

  brillo::SecureBlob fake_data = kFakeData;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_TPM_GetRandom(kDefaultTpm, kFakeSize, _))
      .WillOnce(DoAll(SetArgPointee<2>(fake_data.data()), Return(TPM_SUCCESS)));

  EXPECT_THAT(backend_->GetRandomTpm1().RandomSecureBlob(kFakeSize),
              IsOkAndHolds(kFakeData));
}

}  // namespace hwsec
