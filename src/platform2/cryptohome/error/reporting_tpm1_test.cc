// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>
#include <set>
#include <utility>

#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <gtest/gtest.h>
#include <libhwsec/error/tpm_error.h>
#include <libhwsec/error/tpm1_error.h>
#include <libhwsec-foundation/status/status_chain.h>
#include <metrics/metrics_library_mock.h>

#include "cryptohome/cryptohome_metrics.h"
#include "cryptohome/error/converter.h"
#include "cryptohome/error/cryptohome_tpm_error.h"
#include "cryptohome/error/reporting.h"

namespace cryptohome {

namespace error {

namespace {

using testing::_;
using testing::EndsWith;
using testing::Return;
using testing::StrictMock;

using hwsec::TPM1Error;
using hwsec::TPMError;
using hwsec::unified_tpm_error::kUnifiedErrorBit;
using hwsec_foundation::error::CreateError;
using hwsec_foundation::error::WrapError;
using hwsec_foundation::status::MakeStatus;
using hwsec_foundation::status::StatusChain;

constexpr char kErrorBucketName[] = "Error";

class ErrorReportingTpm1Test : public ::testing::Test {
 public:
  ErrorReportingTpm1Test() = default;

  void SetUp() override { OverrideMetricsLibraryForTesting(&metrics_); }

  void TearDown() override { ClearMetricsLibraryForTesting(); }

 protected:
  StrictMock<MetricsLibraryMock> metrics_;

  const CryptohomeError::ErrorLocationPair kErrorLocationForTesting1 =
      CryptohomeError::ErrorLocationPair(
          static_cast<::cryptohome::error::CryptohomeError::ErrorLocation>(1),
          std::string("Testing1"));
};

constexpr TSS_RESULT kTestingTpmError1 = TSS_E_INVALID_HANDLE | TSS_LAYER_TSP;

TEST_F(ErrorReportingTpm1Test, SimpleTPM1Error) {
  // Setup the expected result.
  EXPECT_CALL(metrics_,
              SendSparseToUMA(EndsWith(kCryptohomeErrorAllLocationsSuffix),
                              kErrorLocationForTesting1.location()))
      .WillOnce(Return(true));
  EXPECT_CALL(metrics_,
              SendSparseToUMA(EndsWith(kCryptohomeErrorAllLocationsSuffix),
                              static_cast<CryptohomeError::ErrorLocation>(
                                  kTestingTpmError1) |
                                  kUnifiedErrorBit))
      .WillOnce(Return(true));
  // HashedStack value is precomputed.
  EXPECT_CALL(
      metrics_,
      SendSparseToUMA(EndsWith(kCryptohomeErrorHashedStackSuffix), 356369525))
      .WillOnce(Return(true));

  // Generate the mixed TPM error.
  CryptohomeError::ErrorLocation mixed =
      static_cast<CryptohomeError::ErrorLocation>(kTestingTpmError1) |
      (kErrorLocationForTesting1.location() << 16);
  EXPECT_CALL(metrics_, SendSparseToUMA(
                            EndsWith(kCryptohomeErrorLeafWithTPMSuffix), mixed))
      .WillOnce(Return(true));

  // Setup the errors.
  auto err1 = CreateError<TPM1Error>(kTestingTpmError1);
  auto err2 = WrapError<TPMError>(std::move(err1), "Testing1");
  auto err3 = MakeStatus<CryptohomeTPMError>(std::move(err2));

  auto err4 =
      MakeStatus<CryptohomeError>(kErrorLocationForTesting1, NoErrorAction(),
                                  user_data_auth::CryptohomeErrorCode::
                                      CRYPTOHOME_ERROR_ACCOUNT_NOT_FOUND)
          .Wrap(std::move(err3));

  user_data_auth::CryptohomeErrorCode legacy_ec;
  user_data_auth::CryptohomeErrorInfo info =
      CryptohomeErrorToUserDataAuthError(err4, &legacy_ec);

  // Make the call.
  ReportCryptohomeError(err4, info, kErrorBucketName);
}

}  // namespace

}  // namespace error

}  // namespace cryptohome
