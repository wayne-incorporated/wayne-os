// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_METRICS_REPORTER_H_
#define MINIOS_METRICS_REPORTER_H_

#include <memory>
#include <string>

#include <base/time/time.h>

#include "metrics/metrics_library.h"
#include "minios/metrics_reporter_interface.h"
#include "minios/process_manager.h"

namespace minios {

extern const char kRecoveryDurationMinutes[];
extern const char kRecoveryReason[];
// Metrics file path in the stateful partition. See:
// init/upstart/send-recovery-metrics.conf
extern const char kStatefulEventsPath[];

extern const int kRecoveryDurationMinutes_Buckets;
extern const int kRecoveryDurationMinutes_MAX;
extern const int kRecoveryReasonCode_NBR;
extern const int kRecoveryReasonCode_MAX;

class MetricsReporter : public MetricsReporterInterface {
 public:
  explicit MetricsReporter(
      ProcessManagerInterface* process_manager,
      std::unique_ptr<MetricsLibraryInterface> metrics_lib = nullptr);
  virtual ~MetricsReporter() = default;

  MetricsReporter(const MetricsReporter&) = delete;
  MetricsReporter& operator=(const MetricsReporter&) = delete;

  void RecordNBRStart() override;
  void ReportNBRComplete() override;

 private:
  std::unique_ptr<MetricsLibraryInterface> metrics_lib_;
  ProcessManagerInterface* process_manager_;

  base::Time start_time_;
};

}  // namespace minios

#endif  // MINIOS_METRICS_REPORTER_H_
