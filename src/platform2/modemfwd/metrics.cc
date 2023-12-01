// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/check.h>
#include <base/logging.h>
#include <dbus/dlcservice/dbus-constants.h>
#include <dbus/modemfwd/dbus-constants.h>

#include "modemfwd/error.h"
#include "modemfwd/logging.h"
#include "modemfwd/metrics.h"

using modemfwd::metrics::CheckForWedgedModemResult;
using modemfwd::metrics::DlcInstallResult;
using modemfwd::metrics::DlcUninstallResult;
using modemfwd::metrics::FwInstallResult;
using modemfwd::metrics::FwUpdateLocation;
using modemfwd::metrics::ModemRecoveryState;
using std::string;

namespace modemfwd {

namespace {

template <typename MetricEnum>
MetricEnum GetMetricFromInnerErrorCode(
    const brillo::Error* err, std::map<std::string, MetricEnum>& result_map) {
  MetricEnum res = MetricEnum::kUnknownError;
  const brillo::Error* err_it = err;
  // Iterate over all errors in the chain and get the deepest error that has a
  // match in the metrics map.
  while (err_it) {
    auto it = result_map.find(err_it->GetCode());
    if (it != result_map.end())
      res = it->second;
    err_it = err_it->GetInnerError();
  }
  return res;
}

}  // namespace

namespace metrics {

const char kMetricCheckForWedgedModemResult[] =
    "Platform.Modemfwd.CheckForWedgedModemResult";
const char kMetricDlcInstallResult[] = "Platform.Modemfwd.DlcInstallResult";
const char kMetricDlcUninstallResult[] = "Platform.Modemfwd.DlcUninstallResult";
const char kMetricFwUpdateLocation[] = "Platform.Modemfwd.FWUpdateLocation";
const char kMetricFwInstallResult[] = "Platform.Modemfwd.FWInstallResult";
const char kMetricFwInstallTime[] = "Platform.Modemfwd.FWInstallTime";
const char kMetricModemRecoveryState[] = "Platform.Modemfwd.ModemRecoveryState";
static constexpr base::TimeDelta kMetricFwInstallTimeMax = base::Minutes(5);
static constexpr base::TimeDelta kMetricFwInstallTimeMin = base::Seconds(1);
static constexpr int kMetricFwInstallTimeNumBuckets = 60;

}  // namespace metrics

// IMPORTANT: To obsolete a metric enum value, just remove it from the map
// initialization and comment it out on the Enum.
Metrics::DlcInstallResultMap Metrics::install_result_ = {
    {dlcservice::kErrorInvalidDlc,
     DlcInstallResult::kDlcServiceReturnedInvalidDlc},  // dbus error
    {dlcservice::kErrorAllocation,
     DlcInstallResult::kDlcServiceReturnedAllocation},  // dbus error
    {dlcservice::kErrorNoImageFound,
     DlcInstallResult::kDlcServiceReturnedNoImageFound},  // dbus error
    {dlcservice::kErrorNeedReboot,
     DlcInstallResult::kDlcServiceReturnedNeedReboot},  // dbus error
    {dlcservice::kErrorBusy,
     DlcInstallResult::kDlcServiceReturnedBusy},  // dbus error
    {error::kUnexpectedDlcState, DlcInstallResult::kFailedUnexpectedDlcState},
    {error::kTimeoutWaitingForDlcService,
     DlcInstallResult::kFailedTimeoutWaitingForDlcService},
    {error::kTimeoutWaitingForDlcInstall,
     DlcInstallResult::kFailedTimeoutWaitingForDlcInstall},
    {error::kTimeoutWaitingForInstalledState,
     DlcInstallResult::kFailedTimeoutWaitingForInstalledState},
    {error::kDlcServiceReturnedErrorOnInstall,
     DlcInstallResult::kDlcServiceReturnedErrorOnInstall},
    {error::kDlcServiceReturnedErrorOnGetDlcState,
     DlcInstallResult::kDlcServiceReturnedErrorOnGetDlcState},
    {error::kUnexpectedEmptyDlcId, DlcInstallResult::kUnexpectedEmptyDlcId},
};

Metrics::DlcUninstallResultMap Metrics::uninstall_result_ = {
    {dlcservice::kErrorInvalidDlc,
     DlcUninstallResult::kDlcServiceReturnedInvalidDlc},  // dbus error
    {dlcservice::kErrorAllocation,
     DlcUninstallResult::kDlcServiceReturnedAllocation},  // dbus error
    {dlcservice::kErrorNoImageFound,
     DlcUninstallResult::kDlcServiceReturnedNoImageFound},  // dbus error
    {dlcservice::kErrorNeedReboot,
     DlcUninstallResult::kDlcServiceReturnedNeedReboot},  // dbus error
    {dlcservice::kErrorBusy,
     DlcUninstallResult::kDlcServiceReturnedBusy},  // dbus error
    {error::kDlcServiceReturnedErrorOnGetExistingDlcs,
     DlcUninstallResult::kDlcServiceReturnedErrorOnGetExistingDlcs},
    {error::kDlcServiceReturnedErrorOnPurge,
     DlcUninstallResult::kDlcServiceReturnedErrorOnPurge},
    {error::kUnexpectedEmptyVariant,
     DlcUninstallResult::kUnexpectedEmptyVariant},
};

Metrics::FwInstallResultMap Metrics::fw_install_result_ = {
    {kErrorResultInitFailure, FwInstallResult::kInitFailure},  // dbus error
    {kErrorResultInitManifestFailure,
     FwInstallResult::kInitManifestFailure},  // dbus error
    {kErrorResultFailedToPrepareFirmwareFile,
     FwInstallResult::kFailedToPrepareFirmwareFile},             // dbus error
    {kErrorResultFlashFailure, FwInstallResult::kFlashFailure},  // dbus error
    {kErrorResultFailureReturnedByHelper,
     FwInstallResult::kFailureReturnedByHelper},  // dbus error
    {kErrorResultInitJournalFailure,
     FwInstallResult::kInitJournalFailure},  // dbus error
    {kErrorResultInitFailureNonLteSku,
     FwInstallResult::kInitFailureNonLteSku},  // dbus error
};

void Metrics::Init() {
  metrics_library_->Init();

  flash_timer_.reset(new chromeos_metrics::TimerReporter(
      metrics::kMetricFwInstallTime,
      metrics::kMetricFwInstallTimeMin.InSeconds(),
      metrics::kMetricFwInstallTimeMax.InSeconds(),
      metrics::kMetricFwInstallTimeNumBuckets));
}

void Metrics::SendDlcInstallResultSuccess() {
  SendDlcInstallResult(DlcInstallResult::kSuccess);
}

void Metrics::SendDlcInstallResultFailure(const brillo::Error* err) {
  DCHECK(err);
  DlcInstallResult res = GetMetricFromInnerErrorCode(err, install_result_);
  SendDlcInstallResult(res);
}

void Metrics::SendDlcInstallResult(DlcInstallResult result) {
  ELOG(INFO) << "SendDlcInstallResult:" << static_cast<int>(result);
  metrics_library_->SendEnumToUMA(
      metrics::kMetricDlcInstallResult, static_cast<int>(result),
      static_cast<int>(DlcInstallResult::kNumConstants));
}

void Metrics::SendDlcUninstallResultSuccess() {
  SendDlcUninstallResult(DlcUninstallResult::kSuccess);
}

void Metrics::SendDlcUninstallResultFailure(const brillo::Error* err) {
  DCHECK(err);
  DlcUninstallResult res = GetMetricFromInnerErrorCode(err, uninstall_result_);
  SendDlcUninstallResult(res);
}

void Metrics::SendDlcUninstallResult(DlcUninstallResult result) {
  ELOG(INFO) << "SendDlcUninstallResult:" << static_cast<int>(result);
  metrics_library_->SendEnumToUMA(
      metrics::kMetricDlcUninstallResult, static_cast<int>(result),
      static_cast<int>(DlcUninstallResult::kNumConstants));
}

// Sends the |FwUpdateLocation| value.
void Metrics::SendFwUpdateLocation(FwUpdateLocation location) {
  ELOG(INFO) << "SendFwUpdateLocation:" << static_cast<int>(location);
  metrics_library_->SendEnumToUMA(
      metrics::kMetricFwUpdateLocation, static_cast<int>(location),
      static_cast<int>(FwUpdateLocation::kNumConstants));
}

void Metrics::SendFwInstallResultSuccess() {
  SendFwInstallResult(FwInstallResult::kSuccess);
}

void Metrics::SendFwInstallResultFailure(const brillo::Error* err) {
  DCHECK(err);
  FwInstallResult res = GetMetricFromInnerErrorCode(err, fw_install_result_);
  SendFwInstallResult(res);
}

void Metrics::SendFwInstallResult(FwInstallResult result) {
  ELOG(INFO) << "SendFwInstallResult:" << static_cast<int>(result);
  metrics_library_->SendEnumToUMA(
      metrics::kMetricFwInstallResult, static_cast<int>(result),
      static_cast<int>(FwInstallResult::kNumConstants));
}

void Metrics::SendModemRecoveryState(ModemRecoveryState state) {
  ELOG(INFO) << "SendModemRecoveryState:" << static_cast<int>(state);
  metrics_library_->SendEnumToUMA(
      metrics::kMetricModemRecoveryState, static_cast<int>(state),
      static_cast<int>(ModemRecoveryState::kNumConstants));
}

void Metrics::SendCheckForWedgedModemResult(CheckForWedgedModemResult result) {
  ELOG(INFO) << "SendCheckForWedgedModemResult:" << static_cast<int>(result);
  metrics_library_->SendEnumToUMA(
      metrics::kMetricCheckForWedgedModemResult, static_cast<int>(result),
      static_cast<int>(CheckForWedgedModemResult::kNumConstants));
}

void Metrics::SendDetailedFwInstallResult(uint32_t firmware_types,
                                          metrics::FwInstallResult res) {
  ::metrics::structured::events::cellular::ModemFwdFwInstallResult()
      .Setfirmware_types(firmware_types)
      .Setfw_install_result(static_cast<int64_t>(res))
      .Record();
}

void Metrics::SendDetailedFwInstallFailureResult(uint32_t firmware_types,
                                                 const brillo::Error* err) {
  FwInstallResult res = GetMetricFromInnerErrorCode(err, fw_install_result_);
  SendDetailedFwInstallResult(firmware_types, res);
}

void Metrics::SendDetailedFwInstallSuccessResult(uint32_t firmware_types) {
  SendDetailedFwInstallResult(firmware_types, FwInstallResult::kSuccess);
}

void Metrics::StartFwFlashTimer() {
  DCHECK(flash_timer_);
  flash_timer_->Start();
}

void Metrics::StopFwFlashTimer() {
  DCHECK(flash_timer_);
  flash_timer_->Stop();
}

void Metrics::SendFwFlashTime() {
  DCHECK(flash_timer_);
  flash_timer_->ReportSeconds();
}

}  // namespace modemfwd
