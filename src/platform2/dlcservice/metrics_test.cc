// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <dbus/dlcservice/dbus-constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <metrics/metrics_library_mock.h>

#include "dlcservice/error.h"
#include "dlcservice/metrics.h"

using dlcservice::metrics::InstallResult;
using dlcservice::metrics::UninstallResult;

namespace dlcservice {

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

TEST_F(MetricsTest, SendInstallResultSuccess_InstalledByUpdateEngine) {
  EXPECT_CALL(
      *metrics_library_,
      SendEnumToUMA(metrics::kMetricInstallResult, 1 /*kSuccessNewInstall*/,
                    static_cast<int>(InstallResult::kNumConstants)));
  metrics_->SendInstallResultSuccess(true);
}

TEST_F(MetricsTest, SendInstallResultSuccess_InstallAlreadyInstalledDlc) {
  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricInstallResult,
                            2 /*kSuccessAlreadyInstalled*/,
                            static_cast<int>(InstallResult::kNumConstants)));
  metrics_->SendInstallResultSuccess(false);
}

TEST_F(MetricsTest, SendInstallResult_UnknownError) {
  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricInstallResult, 0 /*kUnknownError*/,
                            static_cast<int>(InstallResult::kNumConstants)))
      .Times(2);
  auto err = brillo::Error::Create(FROM_HERE, "domain", "some error", "msg");
  metrics_->SendInstallResultFailure(&err);
  err = brillo::Error::Create(
      FROM_HERE, "dbus", "org.chromium.DlcServiceInterface.INTERNAL", "msg");
  metrics_->SendInstallResultFailure(&err);
}

TEST_F(MetricsTest, SendInstallResult_Failures) {
  const int num_consts = static_cast<int>(InstallResult::kNumConstants);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricInstallResult,
                            3 /*kFailedToCreateDirectory*/, num_consts));
  auto err = brillo::Error::Create(FROM_HERE, kDlcErrorDomain,
                                   error::kFailedToCreateDirectory, "msg");
  metrics_->SendInstallResultFailure(&err);
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricInstallResult,
                            4 /*kFailedInstallInUpdateEngine*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, kDlcErrorDomain,
                              error::kFailedInstallInUpdateEngine, "msg");
  metrics_->SendInstallResultFailure(&err);
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricInstallResult,
                            5 /*kErrorInvalidDlc*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, "dbus", kErrorInvalidDlc, "msg");
  metrics_->SendInstallResultFailure(&err);
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricInstallResult,
                            6 /*kErrorNeedReboot*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, "dbus", kErrorNeedReboot, "msg");
  metrics_->SendInstallResultFailure(&err);
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricInstallResult,
                            7 /*kFailedUpdateEngineBusy*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, "dbus", kErrorBusy, "msg");
  metrics_->SendInstallResultFailure(&err);
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricInstallResult,
                            8 /*kFailedToVerifyImage*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, kDlcErrorDomain,
                              error::kFailedToVerifyImage, "msg");
  metrics_->SendInstallResultFailure(&err);
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricInstallResult,
                            9 /*kFailedToMountImage*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, kDlcErrorDomain,
                              error::kFailedToMountImage, "msg");
  metrics_->SendInstallResultFailure(&err);
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricInstallResult,
                            10 /*kFailedNoImageFound*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, kDlcErrorDomain, kErrorNoImageFound,
                              "msg");
  metrics_->SendInstallResultFailure(&err);
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);
  EXPECT_CALL(
      *metrics_library_,
      SendEnumToUMA(metrics::kMetricInstallResult,
                    11 /*kFailedCreationDuringHibernateResume*/, num_consts));
  err =
      brillo::Error::Create(FROM_HERE, kDlcErrorDomain,
                            error::kFailedCreationDuringHibernateResume, "msg");
  metrics_->SendInstallResultFailure(&err);
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  // Check that all values were tested.
  EXPECT_EQ(12, static_cast<int>(InstallResult::kNumConstants));
}

TEST_F(MetricsTest, SendUninstallResult_Success) {
  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricUninstallResult, 1 /*kSuccess*/,
                            static_cast<int>(UninstallResult::kNumConstants)))
      .Times(2);
  metrics_->SendUninstallResult(nullptr);
  brillo::ErrorPtr err;
  metrics_->SendUninstallResult(&err);
}

TEST_F(MetricsTest, SendUninstallResult_UnknownError) {
  EXPECT_CALL(
      *metrics_library_,
      SendEnumToUMA(metrics::kMetricUninstallResult, 0 /*kUnknownError*/,
                    static_cast<int>(UninstallResult::kNumConstants)))
      .Times(2);
  auto err = brillo::Error::Create(FROM_HERE, "domain", "some error", "msg");
  metrics_->SendUninstallResult(&err);
  err = brillo::Error::Create(
      FROM_HERE, "dbus", "org.chromium.DlcServiceInterface.INTERNAL", "msg");
  metrics_->SendUninstallResult(&err);
}

TEST_F(MetricsTest, SendUninstallResult_Failures) {
  const int num_consts = static_cast<int>(UninstallResult::kNumConstants);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricUninstallResult,
                            2 /*kFailedInvalidDlc*/, num_consts));
  auto err = brillo::Error::Create(FROM_HERE, "dbus", kErrorInvalidDlc, "msg");
  metrics_->SendUninstallResult(&err);
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  EXPECT_CALL(*metrics_library_,
              SendEnumToUMA(metrics::kMetricUninstallResult,
                            3 /*kFailedUpdateEngineBusy*/, num_consts));
  err = brillo::Error::Create(FROM_HERE, "dbus", kErrorBusy, "msg");
  metrics_->SendUninstallResult(&err);
  testing::Mock::VerifyAndClearExpectations(&metrics_library_);

  // Check that all values were tested.
  EXPECT_EQ(4, static_cast<int>(UninstallResult::kNumConstants));
}
}  // namespace dlcservice
