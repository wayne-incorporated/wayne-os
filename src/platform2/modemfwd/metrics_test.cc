// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <dbus/dlcservice/dbus-constants.h>
#include <dbus/modemfwd/dbus-constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <metrics/metrics_library_mock.h>

#include "modemfwd/error.h"
#include "modemfwd/metrics.h"

using modemfwd::metrics::CheckForWedgedModemResult;
using modemfwd::metrics::DlcInstallResult;
using modemfwd::metrics::DlcUninstallResult;
using modemfwd::metrics::FwInstallResult;
using modemfwd::metrics::FwUpdateLocation;

namespace modemfwd {

class MetricsTest : public testing::Test {
 public:
  MetricsTest() = default;

 private:
  void SetUp() override {
    auto mock_metrics_library =
        std::make_unique<testing::StrictMock<MetricsLibraryMock>>();
    metrics_library_ = mock_metrics_library.get();
    metrics_ = std::make_unique<Metrics>(std::move(mock_metrics_library));
  }

 protected:
  MetricsLibraryMock* metrics_library_;
  std::unique_ptr<Metrics> metrics_;

 private:
  MetricsTest(const MetricsTest&) = delete;
  MetricsTest& operator=(const MetricsTest&) = delete;
};

TEST_F(MetricsTest, Init) {
  EXPECT_CALL(*metrics_library_, Init());
  metrics_->Init();
}

TEST_F(MetricsTest, SendCheckForWedgedModemResult) {
  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(
                  metrics::kMetricCheckForWedgedModemResult, 0,
                  static_cast<int>(CheckForWedgedModemResult::kNumConstants)));
  metrics_->SendCheckForWedgedModemResult(
      CheckForWedgedModemResult::kModemPresent);
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(
                  metrics::kMetricCheckForWedgedModemResult, 1,
                  static_cast<int>(CheckForWedgedModemResult::kNumConstants)));
  metrics_->SendCheckForWedgedModemResult(
      CheckForWedgedModemResult::kModemPresentAfterReboot);
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(
                  metrics::kMetricCheckForWedgedModemResult, 2,
                  static_cast<int>(CheckForWedgedModemResult::kNumConstants)));
  metrics_->SendCheckForWedgedModemResult(
      CheckForWedgedModemResult::kFailedToRebootModem);
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(
                  metrics::kMetricCheckForWedgedModemResult, 3,
                  static_cast<int>(CheckForWedgedModemResult::kNumConstants)));
  metrics_->SendCheckForWedgedModemResult(
      CheckForWedgedModemResult::kModemWedged);
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(
                  metrics::kMetricCheckForWedgedModemResult, 4,
                  static_cast<int>(CheckForWedgedModemResult::kNumConstants)));
  metrics_->SendCheckForWedgedModemResult(
      CheckForWedgedModemResult::kModemAbsentAfterReboot);
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  // Check that all values were tested.
  EXPECT_EQ(5, static_cast<int>(CheckForWedgedModemResult::kNumConstants));
}

TEST_F(MetricsTest, SendDlcInstallResultSuccess) {
  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricDlcInstallResult, 1 /*kSuccess*/,
                            static_cast<int>(DlcInstallResult::kNumConstants)));
  metrics_->SendDlcInstallResultSuccess();
}

TEST_F(MetricsTest, SendDlcInstallResult_UnknownError) {
  EXPECT_CALL(
      *metrics_library_,
      SendEnumToUMA(metrics::kMetricDlcInstallResult, 0 /*kUnknownError*/,
                    static_cast<int>(DlcInstallResult::kNumConstants)))
      .Times(2);
  auto err = brillo::Error::Create(FROM_HERE, "domain", "some error", "msg");
  metrics_->SendDlcInstallResultFailure(err.get());
  err = brillo::Error::Create(FROM_HERE, "dbus",
                              "org.chromium.ModemfwdInterface.INTERNAL", "msg");
  metrics_->SendDlcInstallResultFailure(err.get());
}

TEST_F(MetricsTest, SendDlcInstallResult_Failures) {
  const int num_consts = static_cast<int>(DlcInstallResult::kNumConstants);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricDlcInstallResult,
                            2 /*kDlcServiceReturnedInvalidDlc*/, num_consts));
  auto err = brillo::Error::Create(FROM_HERE, "dbus",
                                   dlcservice::kErrorInvalidDlc, "msg");
  metrics_->SendDlcInstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricDlcInstallResult,
                            3 /*kDlcServiceReturnedAllocation*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, "dbus", dlcservice::kErrorAllocation,
                              "msg");
  metrics_->SendDlcInstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricDlcInstallResult,
                            4 /*kDlcServiceReturnedNoImageFound*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, "dbus", dlcservice::kErrorNoImageFound,
                              "msg");
  metrics_->SendDlcInstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricDlcInstallResult,
                            5 /*kDlcServiceReturnedNeedReboot*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, "dbus", dlcservice::kErrorNeedReboot,
                              "msg");
  metrics_->SendDlcInstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricDlcInstallResult,
                            6 /*kDlcServiceReturnedBusy*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, "dbus", dlcservice::kErrorBusy, "msg");
  metrics_->SendDlcInstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricDlcInstallResult,
                            7 /*kFailedUnexpectedDlcState*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, "dbus", error::kUnexpectedDlcState,
                              "msg");
  metrics_->SendDlcInstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(
      *metrics_library_,
      SendEnumToUMA(metrics::kMetricDlcInstallResult,
                    8 /*kFailedTimeoutWaitingForDlcService*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, "dbus",
                              error::kTimeoutWaitingForDlcService, "msg");
  metrics_->SendDlcInstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(
      *metrics_library_,
      SendEnumToUMA(metrics::kMetricDlcInstallResult,
                    9 /*kFailedTimeoutWaitingForDlcInstall*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, "dbus",
                              error::kTimeoutWaitingForDlcInstall, "msg");
  metrics_->SendDlcInstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(
      *metrics_library_,
      SendEnumToUMA(metrics::kMetricDlcInstallResult,
                    10 /*kFailedTimeoutWaitingForInstalledState*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, "dbus",
                              error::kTimeoutWaitingForInstalledState, "msg");
  metrics_->SendDlcInstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(
      *metrics_library_,
      SendEnumToUMA(metrics::kMetricDlcInstallResult,
                    11 /*kDlcServiceReturnedErrorOnInstall*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, "dbus",
                              error::kDlcServiceReturnedErrorOnInstall, "msg");
  metrics_->SendDlcInstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(
      *metrics_library_,
      SendEnumToUMA(metrics::kMetricDlcInstallResult,
                    12 /*kDlcServiceReturnedErrorOnGetDlcState*/, num_consts));
  err = brillo::Error::Create(
      FROM_HERE, "dbus", error::kDlcServiceReturnedErrorOnGetDlcState, "msg");
  metrics_->SendDlcInstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricDlcInstallResult,
                            13 /*kUnexpectedEmptyDlcId*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, "dbus", error::kUnexpectedEmptyDlcId,
                              "msg");
  metrics_->SendDlcInstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  // Check that all values were tested.
  EXPECT_EQ(14, static_cast<int>(DlcInstallResult::kNumConstants));
}

TEST_F(MetricsTest, SendDlcInstallResult_VerifyErrorIteration) {
  const int num_consts = static_cast<int>(DlcInstallResult::kNumConstants);

  EXPECT_CALL(
      *metrics_library_,
      SendEnumToUMA(
          metrics::kMetricDlcInstallResult,
          static_cast<int>(DlcInstallResult::kDlcServiceReturnedInvalidDlc),
          num_consts))
      .Times(3);
  // known root error
  auto err = brillo::Error::Create(FROM_HERE, "dbus",
                                   dlcservice::kErrorInvalidDlc, "msg");
  // known linked error
  brillo::Error::AddTo(&err, FROM_HERE, kModemfwdErrorDomain,
                       error::kDlcServiceReturnedErrorOnInstall, "msg");
  metrics_->SendDlcInstallResultFailure(err.get());

  // unknown root error
  err = brillo::Error::Create(FROM_HERE, "dbus", "unknown_error", "msg");
  // known linked error
  brillo::Error::AddTo(&err, FROM_HERE, "dbus", dlcservice::kErrorInvalidDlc,
                       "msg");
  metrics_->SendDlcInstallResultFailure(err.get());

  // unknown root error
  err = brillo::Error::Create(FROM_HERE, "dbus", "unknown_error", "msg");
  // known linked error
  brillo::Error::AddTo(&err, FROM_HERE, "dbus", dlcservice::kErrorInvalidDlc,
                       "msg");
  // unknown linked error
  brillo::Error::AddTo(&err, FROM_HERE, "dbus", "unknown_error2", "msg");
  metrics_->SendDlcInstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricDlcInstallResult,
                            static_cast<int>(DlcInstallResult::kUnknownError),
                            num_consts));
  // unknown root error
  err = brillo::Error::Create(FROM_HERE, "dbus", "unknown_error", "msg");
  // unknown linked error
  brillo::Error::AddTo(&err, FROM_HERE, "dbus", "unknown_error2", "msg");
  metrics_->SendDlcInstallResultFailure(err.get());
}

TEST_F(MetricsTest, SendDlcUninstallResultSuccess) {
  EXPECT_CALL(
      *metrics_library_,
      SendEnumToUMA(metrics::kMetricDlcUninstallResult, 1 /*kSuccess*/,
                    static_cast<int>(DlcUninstallResult::kNumConstants)))
      .Times(1);
  metrics_->SendDlcUninstallResultSuccess();
}

TEST_F(MetricsTest, SendDlcUninstallResult_UnknownError) {
  EXPECT_CALL(
      *metrics_library_,
      SendEnumToUMA(metrics::kMetricDlcUninstallResult, 0 /*kUnknownError*/,
                    static_cast<int>(DlcUninstallResult::kNumConstants)))
      .Times(2);
  auto err = brillo::Error::Create(FROM_HERE, "domain", "some error", "msg");
  metrics_->SendDlcUninstallResultFailure(err.get());
  err = brillo::Error::Create(FROM_HERE, "dbus",
                              "org.chromium.ModemfwdInterface.INTERNAL", "msg");
  metrics_->SendDlcUninstallResultFailure(err.get());
}

TEST_F(MetricsTest, SendDlcUninstallResult_Failures) {
  const int num_consts = static_cast<int>(DlcUninstallResult::kNumConstants);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricDlcUninstallResult,
                            2 /*kDlcServiceReturnedInvalidDlc*/, num_consts));
  auto err = brillo::Error::Create(FROM_HERE, "dbus",
                                   dlcservice::kErrorInvalidDlc, "msg");
  metrics_->SendDlcUninstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricDlcUninstallResult,
                            3 /*kDlcServiceReturnedAllocation*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, "dbus", dlcservice::kErrorAllocation,
                              "msg");
  metrics_->SendDlcUninstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricDlcUninstallResult,
                            4 /*kDlcServiceReturnedNoImageFound*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, "dbus", dlcservice::kErrorNoImageFound,
                              "msg");
  metrics_->SendDlcUninstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricDlcUninstallResult,
                            5 /*kDlcServiceReturnedNeedReboot*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, "dbus", dlcservice::kErrorNeedReboot,
                              "msg");
  metrics_->SendDlcUninstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricDlcUninstallResult,
                            6 /*kDlcServiceReturnedBusy*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, "dbus", dlcservice::kErrorBusy, "msg");
  metrics_->SendDlcUninstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricDlcUninstallResult,
                            7 /*kDlcServiceReturnedErrorOnGetExistingDlcs*/,
                            num_consts));
  err = brillo::Error::Create(FROM_HERE, "dbus",
                              error::kDlcServiceReturnedErrorOnGetExistingDlcs,
                              "msg");
  metrics_->SendDlcUninstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricDlcUninstallResult,
                            8 /*kDlcServiceReturnedErrorOnPurge*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, "dbus",
                              error::kDlcServiceReturnedErrorOnPurge, "msg");
  metrics_->SendDlcUninstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricDlcUninstallResult,
                            9 /*kUnexpectedEmptyVariant*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, "dbus", error::kUnexpectedEmptyVariant,
                              "msg");
  metrics_->SendDlcUninstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  // Check that all values were tested.
  EXPECT_EQ(10, static_cast<int>(DlcUninstallResult::kNumConstants));
}

TEST_F(MetricsTest, SendDlcUninstallResult_VerifyErrorIteration) {
  const int num_consts = static_cast<int>(DlcUninstallResult::kNumConstants);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(
                  metrics::kMetricDlcUninstallResult,
                  static_cast<int>(DlcUninstallResult::kUnexpectedEmptyVariant),
                  num_consts))
      .Times(3);
  // known root error
  auto err = brillo::Error::Create(FROM_HERE, "dbus",
                                   error::kUnexpectedEmptyVariant, "msg");
  // known linked error
  brillo::Error::AddTo(&err, FROM_HERE, kModemfwdErrorDomain,
                       error::kDlcServiceReturnedErrorOnGetExistingDlcs, "msg");
  metrics_->SendDlcUninstallResultFailure(err.get());

  // unknown root error
  err = brillo::Error::Create(FROM_HERE, "dbus", "unknown_error", "msg");
  // known linked error
  brillo::Error::AddTo(&err, FROM_HERE, "dbus", error::kUnexpectedEmptyVariant,
                       "msg");
  metrics_->SendDlcUninstallResultFailure(err.get());

  // unknown root error
  err = brillo::Error::Create(FROM_HERE, "dbus", "unknown_error", "msg");
  // known linked error
  brillo::Error::AddTo(&err, FROM_HERE, "dbus", error::kUnexpectedEmptyVariant,
                       "msg");
  // unknown linked error
  brillo::Error::AddTo(&err, FROM_HERE, "dbus", "unknown_error2", "msg");
  metrics_->SendDlcUninstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricDlcUninstallResult,
                            static_cast<int>(DlcUninstallResult::kUnknownError),
                            num_consts));
  // unknown root error
  err = brillo::Error::Create(FROM_HERE, "dbus", "unknown_error", "msg");
  // unknown linked error
  brillo::Error::AddTo(&err, FROM_HERE, "dbus", "unknown_error2", "msg");
  metrics_->SendDlcUninstallResultFailure(err.get());
}

TEST_F(MetricsTest, SendFwUpdateLocation) {
  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricFwUpdateLocation, 0,
                            static_cast<int>(FwUpdateLocation::kNumConstants)));
  metrics_->SendFwUpdateLocation(FwUpdateLocation::kRootFS);
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricFwUpdateLocation, 1,
                            static_cast<int>(FwUpdateLocation::kNumConstants)));
  metrics_->SendFwUpdateLocation(FwUpdateLocation::kDlc);
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricFwUpdateLocation, 2,
                            static_cast<int>(FwUpdateLocation::kNumConstants)));
  metrics_->SendFwUpdateLocation(FwUpdateLocation::kFallbackToRootFS);
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  // Check that all values were tested.
  EXPECT_EQ(3, static_cast<int>(FwUpdateLocation::kNumConstants));
}

TEST_F(MetricsTest, SendFwInstallResultSuccess) {
  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricFwInstallResult, 1 /*kSuccess*/,
                            static_cast<int>(FwInstallResult::kNumConstants)));
  metrics_->SendFwInstallResultSuccess();
}

TEST_F(MetricsTest, SendFwInstallResult_UnknownError) {
  EXPECT_CALL(
      *metrics_library_,
      SendEnumToUMA(metrics::kMetricFwInstallResult, 0 /*kUnknownError*/,
                    static_cast<int>(FwInstallResult::kNumConstants)))
      .Times(2);
  auto err = brillo::Error::Create(FROM_HERE, "domain", "some error", "msg");
  metrics_->SendFwInstallResultFailure(err.get());
  err = brillo::Error::Create(FROM_HERE, "dbus",
                              "org.chromium.ModemfwdInterface.INTERNAL", "msg");
  metrics_->SendFwInstallResultFailure(err.get());
}

TEST_F(MetricsTest, SendFwInstallResult_Failures) {
  const int num_consts = static_cast<int>(FwInstallResult::kNumConstants);

  EXPECT_CALL(*metrics_library_, SendEnumToUMA(metrics::kMetricFwInstallResult,
                                               2 /*kInitFailure*/, num_consts));
  auto err =
      brillo::Error::Create(FROM_HERE, "dbus", kErrorResultInitFailure, "msg");
  metrics_->SendFwInstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricFwInstallResult,
                            3 /*kInitManifestFailure*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, "dbus",
                              kErrorResultInitManifestFailure, "msg");
  metrics_->SendFwInstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricFwInstallResult,
                            4 /*kFailedToPrepareFirmwareFile*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, "dbus",
                              kErrorResultFailedToPrepareFirmwareFile, "msg");
  metrics_->SendFwInstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricFwInstallResult,
                            5 /*kFlashFailure*/, num_consts));
  err =
      brillo::Error::Create(FROM_HERE, "dbus", kErrorResultFlashFailure, "msg");
  metrics_->SendFwInstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricFwInstallResult,
                            6 /*kFailureReturnedByHelper*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, "dbus",
                              kErrorResultFailureReturnedByHelper, "msg");
  metrics_->SendFwInstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricFwInstallResult,
                            7 /*kInitJournalFailure*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, "dbus", kErrorResultInitJournalFailure,
                              "msg");
  metrics_->SendFwInstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricFwInstallResult,
                            8 /*kInitFailureNonLteSku*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, "dbus",
                              kErrorResultInitFailureNonLteSku, "msg");
  metrics_->SendFwInstallResultFailure(err.get());
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  // Check that all values were tested.
  EXPECT_EQ(9, static_cast<int>(FwInstallResult::kNumConstants));
}
}  // namespace modemfwd
