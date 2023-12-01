// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/functional/bind.h>
#include <base/numerics/safe_conversions.h>
#include <base/time/time.h>

#include "hps/hps_metrics.h"

namespace hps {

constexpr int kHpsUpdateMcuMaxDurationMilliSeconds = 60 * 1000;
constexpr int kHpsUpdateSpiMaxDurationMilliSeconds = 40 * 60 * 1000;
constexpr int kHpsBootMaxDurationMilliSeconds =
    kHpsUpdateMcuMaxDurationMilliSeconds +
    kHpsUpdateSpiMaxDurationMilliSeconds + 10 * 60 * 1000;

// chromeos_metrics::CumulativeMetrics constants:
constexpr char kCumulativeMetricsBackingDir[] = "/var/lib/hpsd/metrics";
constexpr double kMinimumObservedImagesForValidityMetricUpload = 30.;

HpsMetrics::HpsMetrics()
    : HpsMetrics(base::FilePath(kCumulativeMetricsBackingDir)) {}

HpsMetrics::HpsMetrics(base::FilePath cumulative_metrics_path)
    : metrics_lib_(std::make_unique<MetricsLibrary>()),
      cumulative_metrics_(cumulative_metrics_path,
                          {"invalid", "valid"},
                          kUpdatePeriod,
                          base::BindRepeating(&HpsMetrics::UpdateValidityStats,
                                              base::Unretained(this)),
                          kAccumulatePeriod,
                          base::BindRepeating(&HpsMetrics::ReportValidityStats,
                                              base::Unretained(this))) {}

void HpsMetrics::SendImageValidity(bool valid) {
  validity_counters_[valid] += 1;
}

void HpsMetrics::UpdateValidityStats(chromeos_metrics::CumulativeMetrics* cm) {
  if (validity_counters_[false] || validity_counters_[true]) {
    cumulative_metrics_.Add("invalid", validity_counters_[false]);
    validity_counters_[false] = 0;
    cumulative_metrics_.Add("valid", validity_counters_[true]);
    validity_counters_[true] = 0;
  }
}

void HpsMetrics::ReportValidityStats(chromeos_metrics::CumulativeMetrics* cm) {
  double valid = base::checked_cast<double>(cumulative_metrics_.Get("valid"));
  double invalid =
      base::checked_cast<double>(cumulative_metrics_.Get("invalid"));
  if (valid + invalid >= kMinimumObservedImagesForValidityMetricUpload) {
    // ceil the value so that 1 invalid image will push the value above the 0
    // bucket
    metrics_lib_->SendToUMA(
        kHpsImageInvalidity,
        base::ClampCeil(1000.0 * invalid / (valid + invalid)), 0, 1000, 100);
  }
}

bool HpsMetrics::SendHpsTurnOnResult(HpsTurnOnResult result,
                                     base::TimeDelta duration) {
  switch (result) {
    case HpsTurnOnResult::kSuccess:
      metrics_lib_->SendToUMA(kHpsBootSuccessDuration,
                              static_cast<int>(duration.InMilliseconds()), 1,
                              kHpsBootMaxDurationMilliSeconds, 50);
      break;
    // The kHpsBoot*Duration is only for terminal boot status, (fail or
    // succeed). So for the 'send an update' results, do not send the duration.
    case HpsTurnOnResult::kMcuVersionMismatch:
    case HpsTurnOnResult::kSpiNotVerified:
    case HpsTurnOnResult::kMcuNotVerified:
    case HpsTurnOnResult::kPowerOnRecoverySucceeded:
      break;
    case HpsTurnOnResult::kStage1NotStarted:
    case HpsTurnOnResult::kApplNotStarted:
    case HpsTurnOnResult::kNoResponse:
    case HpsTurnOnResult::kTimeout:
    case HpsTurnOnResult::kBadMagic:
    case HpsTurnOnResult::kFault:
    case HpsTurnOnResult::kMcuUpdateFailure:
    case HpsTurnOnResult::kSpiUpdateFailure:
    case HpsTurnOnResult::kMcuUpdatedThenFailed:
    case HpsTurnOnResult::kSpiUpdatedThenFailed:
    case HpsTurnOnResult::kPowerOnRecoveryFailed:
      metrics_lib_->SendToUMA(kHpsBootFailedDuration,
                              static_cast<int>(duration.InMilliseconds()), 1,
                              kHpsBootMaxDurationMilliSeconds, 50);
      break;
  }
  return metrics_lib_->SendEnumToUMA(hps::kHpsTurnOnResult, result);
}

bool HpsMetrics::SendHpsUpdateDuration(HpsBank bank, base::TimeDelta duration) {
  switch (bank) {
    case HpsBank::kMcuFlash:
      return metrics_lib_->SendToUMA(
          kHpsUpdateMcuDuration, static_cast<int>(duration.InMilliseconds()), 1,
          kHpsUpdateMcuMaxDurationMilliSeconds, 50);
    // The bank here is kSpiFlash, but the timing is for both kSpiFlash and
    // kSocRom
    case HpsBank::kSpiFlash:
      return metrics_lib_->SendToUMA(
          kHpsUpdateSpiDuration, static_cast<int>(duration.InMilliseconds()), 1,
          kHpsUpdateSpiMaxDurationMilliSeconds, 50);
    case HpsBank::kSocRom:
      break;
  }
  return true;
}

}  // namespace hps
