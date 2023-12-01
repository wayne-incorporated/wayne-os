// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_MINIDIAG_MINIDIAG_METRICS_H_
#define DIAGNOSTICS_CROS_MINIDIAG_MINIDIAG_METRICS_H_

#include <string>

#include <base/time/time.h>
#include <metrics/metrics_library.h>

#include "diagnostics/cros_minidiag/minidiag_metrics_names.h"

namespace cros_minidiag {

// This class provides wrapping functions for callers to report ChromeOS
// elog-related metrics without bothering to know all the constant declarations.
class MiniDiagMetrics : private MetricsLibrary {
 public:
  MiniDiagMetrics();
  MiniDiagMetrics(const MiniDiagMetrics&) = delete;
  MiniDiagMetrics operator=(const MiniDiagMetrics&) = delete;
  ~MiniDiagMetrics();

  // Report Platform.MiniDiag.Launch event.
  void RecordLaunch(int count) const;
  // Report Platform.MiniDiag.[Type].Result and
  // Platform.MiniDiag.[Type].OpenDuration events.
  void RecordTestReport(const std::string& type,
                        const std::string& result,
                        const base::TimeDelta& time) const;
  // Report Platform.MiniDiag.OpenDuration.
  void RecordOpenDuration(const base::TimeDelta& time) const;

  void SetMetricsLibraryForTesting(MetricsLibraryInterface* metrics_library) {
    metrics_library_ = metrics_library;
  }

 private:
  MetricsLibraryInterface* metrics_library_{this};
  // UMA accepts int, not int64_t, so we need to check before casting.
  bool IsTimeValid(const base::TimeDelta& time) const;
};
}  // namespace cros_minidiag

#endif  // DIAGNOSTICS_CROS_MINIDIAG_MINIDIAG_METRICS_H_
