// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>
#include <set>
#include <string>
#include <utility>

#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <gtest/gtest.h>
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

using hwsec::TPMError;
using hwsec::unified_tpm_error::kUnifiedErrorBit;
using hwsec_foundation::error::CreateError;
using hwsec_foundation::error::WrapError;
using hwsec_foundation::status::MakeStatus;
using hwsec_foundation::status::OkStatus;
using hwsec_foundation::status::StatusChain;

constexpr char kErrorBucketName[] = "Error";

class ErrorReportingTest : public ::testing::Test {
 public:
  ErrorReportingTest() = default;

  void SetUp() override { OverrideMetricsLibraryForTesting(&metrics_); }

  void TearDown() override { ClearMetricsLibraryForTesting(); }

 protected:
  StrictMock<MetricsLibraryMock> metrics_;

  const CryptohomeError::ErrorLocationPair kErrorLocationForTesting1 =
      CryptohomeError::ErrorLocationPair(
          static_cast<::cryptohome::error::CryptohomeError::ErrorLocation>(1),
          std::string("Testing1"));
  const CryptohomeError::ErrorLocationPair kErrorLocationForTesting2 =
      CryptohomeError::ErrorLocationPair(
          static_cast<::cryptohome::error::CryptohomeError::ErrorLocation>(2),
          std::string("Testing2"));
};

TEST_F(ErrorReportingTest, SuccessNoReporting) {
  EXPECT_CALL(metrics_, SendSparseToUMA(_, _)).Times(0);

  auto err1 = OkStatus<CryptohomeError>();
  user_data_auth::CryptohomeErrorInfo info;
  ReportCryptohomeError(err1, info, kErrorBucketName);
}

TEST_F(ErrorReportingTest, ReportSuccess) {
  EXPECT_CALL(metrics_,
              SendSparseToUMA(EndsWith(kCryptohomeErrorLeafWithTPMSuffix), 0))
      .Times(2)
      .WillRepeatedly(Return(true));
  ReportCryptohomeOk(kErrorBucketName);

  auto success = OkStatus<CryptohomeError>();
  // This should have the same effect as ReportCryptohomeOk.
  ReportOperationStatus(success, kErrorBucketName);
}

TEST_F(ErrorReportingTest, NoTPMError) {
  // Setup the expected result.
  EXPECT_CALL(metrics_,
              SendSparseToUMA(EndsWith(kCryptohomeErrorAllLocationsSuffix),
                              kErrorLocationForTesting1.location()))
      .Times(2)
      .WillRepeatedly(Return(true));
  EXPECT_CALL(metrics_,
              SendSparseToUMA(EndsWith(kCryptohomeErrorAllLocationsSuffix),
                              kErrorLocationForTesting2.location()))
      .Times(2)
      .WillRepeatedly(Return(true));
  EXPECT_CALL(metrics_,
              SendSparseToUMA(EndsWith(kCryptohomeErrorLeafWithoutTPMSuffix),
                              kErrorLocationForTesting1.location()))
      .Times(2)
      .WillRepeatedly(Return(true));
  EXPECT_CALL(metrics_,
              SendSparseToUMA(EndsWith(kCryptohomeErrorLeafWithTPMSuffix),
                              kErrorLocationForTesting1.location() << 16))
      .Times(2)
      .WillRepeatedly(Return(true));
  // HashedStack value is precomputed.
  EXPECT_CALL(
      metrics_,
      SendSparseToUMA(EndsWith(kCryptohomeErrorHashedStackSuffix), -960165467))
      .Times(2)
      .WillRepeatedly(Return(true));

  // Setup the errors.
  auto err1 = MakeStatus<CryptohomeError>(
      kErrorLocationForTesting1, NoErrorAction(),
      user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_ACCOUNT_NOT_FOUND);

  auto err2 =
      MakeStatus<CryptohomeError>(kErrorLocationForTesting2, NoErrorAction(),
                                  user_data_auth::CryptohomeErrorCode::
                                      CRYPTOHOME_ERROR_ACCOUNT_NOT_FOUND)
          .Wrap(std::move(err1));

  user_data_auth::CryptohomeErrorCode legacy_ec;
  user_data_auth::CryptohomeErrorInfo info =
      CryptohomeErrorToUserDataAuthError(err2, &legacy_ec);

  // Make the call.
  ReportCryptohomeError(err2, info, kErrorBucketName);
  // This should have the same effect as ReportCryptohomeError.
  ReportOperationStatus(err2, kErrorBucketName);
}

TEST_F(ErrorReportingTest, DevCheckUnexpectedState) {
  // Setup the uninteresting stuffs first.
  EXPECT_CALL(metrics_,
              SendSparseToUMA(EndsWith(kCryptohomeErrorAllLocationsSuffix), _))
      .Times(2);
  EXPECT_CALL(metrics_, SendSparseToUMA(
                            EndsWith(kCryptohomeErrorLeafWithoutTPMSuffix), _))
      .Times(1);
  EXPECT_CALL(metrics_,
              SendSparseToUMA(EndsWith(kCryptohomeErrorLeafWithTPMSuffix), _))
      .Times(1);
  EXPECT_CALL(metrics_,
              SendSparseToUMA(EndsWith(kCryptohomeErrorHashedStackSuffix), _))
      .Times(1);

  // Make sure kDevCheckUnexpectedState is notified.
  EXPECT_CALL(metrics_,
              SendSparseToUMA(
                  EndsWith(kCryptohomeErrorDevCheckUnexpectedStateSuffix), 1))
      .Times(1);

  // Setup the errors.
  auto err1 = MakeStatus<CryptohomeError>(
      kErrorLocationForTesting1,
      ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
      user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_ACCOUNT_NOT_FOUND);

  auto err2 =
      MakeStatus<CryptohomeError>(kErrorLocationForTesting2, NoErrorAction(),
                                  user_data_auth::CryptohomeErrorCode::
                                      CRYPTOHOME_ERROR_ACCOUNT_NOT_FOUND)
          .Wrap(std::move(err1));

  user_data_auth::CryptohomeErrorCode legacy_ec;
  user_data_auth::CryptohomeErrorInfo info =
      CryptohomeErrorToUserDataAuthError(err2, &legacy_ec);

  // Make the call.
  ReportCryptohomeError(err2, info, kErrorBucketName);
}

TEST_F(ErrorReportingTest, GenericTPMError) {
  // Setup the expected result.
  EXPECT_CALL(metrics_,
              SendSparseToUMA(EndsWith(kCryptohomeErrorAllLocationsSuffix),
                              kErrorLocationForTesting1.location()))
      .WillOnce(Return(true));
  // 32527 is precomputed value for "Testing1"
  CryptohomeError::ErrorLocation kHashedTesting1 = 32527;
  EXPECT_CALL(metrics_,
              SendSparseToUMA(EndsWith(kCryptohomeErrorAllLocationsSuffix),
                              kHashedTesting1 | kUnifiedErrorBit))
      .WillOnce(Return(true));
  // HashedStack value is precomputed.
  EXPECT_CALL(
      metrics_,
      SendSparseToUMA(EndsWith(kCryptohomeErrorHashedStackSuffix), -1732565939))
      .WillOnce(Return(true));

  // Generate the mixed TPM error.
  CryptohomeError::ErrorLocation mixed =
      kHashedTesting1 | (kErrorLocationForTesting1.location() << 16);
  EXPECT_CALL(metrics_, SendSparseToUMA(
                            EndsWith(kCryptohomeErrorLeafWithTPMSuffix), mixed))
      .WillOnce(Return(true));

  // Setup the errors.
  auto err1 =
      CreateError<TPMError>("Testing1", hwsec::TPMRetryAction::kSession);
  auto err2 = WrapError<TPMError>(std::move(err1), "Testing2");
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
