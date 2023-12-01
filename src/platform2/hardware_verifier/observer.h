/* Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef HARDWARE_VERIFIER_OBSERVER_H_
#define HARDWARE_VERIFIER_OBSERVER_H_

#include <map>
#include <memory>
#include <string>

#include <base/no_destructor.h>
#include <base/time/time.h>
#include <metrics/metrics_library.h>

#include "hardware_verifier/hardware_verifier.pb.h"

namespace hardware_verifier {

// Total time to finish execution (initialization + probing + verification).
constexpr auto kMetricTimeToFinish = "ChromeOS.HardwareVerifier.TimeToFinish";

// Total time to finish probing.
constexpr auto kMetricTimeToProbe = "ChromeOS.HardwareVerifier.TimeToProbe";

// Prefix for VerificationReport items.
constexpr auto kMetricVerifierReportPrefix =
    "ChromeOS.HardwareVerifier.Report.";

// The entire program should end within one minutes, so it should be safe to
// assume that all timer samples should be a value in range [0, 60 * 1000] ms.
const int kTimerMinMs_ = 0;
const int kTimerMaxMs_ = 60 * 1000;
// Maximum recommended value.
const int kTimerBuckets_ = 50;

// Observe and potentially logs the behavior of hardware_verifier.
class Observer {
 public:
  static Observer* GetInstance();

  void StartTimer(const std::string& timer_name);
  void StopTimer(const std::string& timer_name);

  void SetMetricsLibrary(std::unique_ptr<MetricsLibraryInterface> metrics);

  void RecordHwVerificationReport(const HwVerificationReport&);

 private:
  friend class base::NoDestructor<Observer>;

  Observer() = default;
  Observer(const Observer&) = delete;
  Observer& operator=(const Observer&) = delete;

  std::map<std::string, base::TimeTicks> timers_;
  std::unique_ptr<MetricsLibraryInterface> metrics_;
};

}  // namespace hardware_verifier

#endif  // HARDWARE_VERIFIER_OBSERVER_H_
