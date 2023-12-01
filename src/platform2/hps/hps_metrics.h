// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HPS_HPS_METRICS_H_
#define HPS_HPS_METRICS_H_

#include <array>
#include <memory>
#include <utility>

#include <metrics/cumulative_metrics.h>
#include <metrics/metrics_library.h>
#include <base/time/time.h>

#include "hps/hps_reg.h"

namespace hps {

constexpr char kHpsTurnOnResult[] = "ChromeOS.HPS.TurnOn.Result";
constexpr char kHpsBootFailedDuration[] = "ChromeOS.HPS.TurnOn.Failed.Duration";
constexpr char kHpsBootSuccessDuration[] =
    "ChromeOS.HPS.TurnOn.Success.Duration";
constexpr char kHpsUpdateMcuDuration[] = "ChromeOS.HPS.Update.Mcu.Duration";
constexpr char kHpsUpdateSpiDuration[] = "ChromeOS.HPS.Update.Spi.Duration";
constexpr char kHpsImageInvalidity[] = "ChromeOS.HPS.Image.Invalidity";

constexpr base::TimeDelta kUpdatePeriod = base::Minutes(1);
constexpr base::TimeDelta kAccumulatePeriod = base::Minutes(10);

// These values are logged to UMA. Entries should not be renumbered and
// numeric values should never be reused. Please keep in sync with
// "HpsTurnOnResult" in tools/metrics/histograms/enums.xml in the Chromium repo.
enum class HpsTurnOnResult {
  kSuccess = 0,
  kMcuVersionMismatch = 1,
  kSpiNotVerified = 2,
  kMcuNotVerified = 3,
  kStage1NotStarted = 4,
  kApplNotStarted = 5,
  kNoResponse = 6,
  kTimeout = 7,
  kBadMagic = 8,
  kFault = 9,
  kMcuUpdateFailure = 10,
  kSpiUpdateFailure = 11,
  kMcuUpdatedThenFailed = 12,
  kSpiUpdatedThenFailed = 13,
  kPowerOnRecoverySucceeded = 14,
  kPowerOnRecoveryFailed = 15,
  kMaxValue = kPowerOnRecoveryFailed,
};

class HpsMetricsInterface {
 public:
  virtual ~HpsMetricsInterface() {}

  virtual bool SendHpsTurnOnResult(HpsTurnOnResult result,
                                   base::TimeDelta duration) = 0;
  virtual bool SendHpsUpdateDuration(HpsBank bank,
                                     base::TimeDelta duration) = 0;
  virtual void SendImageValidity(bool valid) = 0;
};

class HpsMetrics : public HpsMetricsInterface {
 public:
  HpsMetrics();
  // Specify path for testing
  explicit HpsMetrics(base::FilePath cumulative_metrics_path);
  HpsMetrics(const HpsMetrics&) = delete;
  HpsMetrics& operator=(const HpsMetrics&) = delete;

  ~HpsMetrics() override = default;

  bool SendHpsTurnOnResult(HpsTurnOnResult result,
                           base::TimeDelta duration) override;
  bool SendHpsUpdateDuration(HpsBank bank, base::TimeDelta duration) override;
  void SendImageValidity(bool valid) override;
  void UpdateValidityStats(chromeos_metrics::CumulativeMetrics* cm);
  void ReportValidityStats(chromeos_metrics::CumulativeMetrics* cm);

  void SetMetricsLibraryForTesting(
      std::unique_ptr<MetricsLibraryInterface> metrics_lib) {
    metrics_lib_ = std::move(metrics_lib);
  }

  MetricsLibraryInterface* metrics_library_for_testing() {
    return metrics_lib_.get();
  }

 private:
  std::unique_ptr<MetricsLibraryInterface> metrics_lib_;
  chromeos_metrics::CumulativeMetrics cumulative_metrics_;
  std::array<int64_t, 2> validity_counters_ = {0, 0};
};

class HpsNoMetrics : public HpsMetricsInterface {
 public:
  HpsNoMetrics() {}
  HpsNoMetrics(const HpsNoMetrics&) = delete;
  HpsNoMetrics& operator=(const HpsNoMetrics&) = delete;

  ~HpsNoMetrics() override = default;

  bool SendHpsTurnOnResult(HpsTurnOnResult result,
                           base::TimeDelta duration) override {
    return true;
  }
  bool SendHpsUpdateDuration(HpsBank bank, base::TimeDelta duration) override {
    return true;
  }
  void SendImageValidity(bool valid) override {}
};

}  // namespace hps

#endif  // HPS_HPS_METRICS_H_
