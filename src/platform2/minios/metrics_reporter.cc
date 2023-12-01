// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/time/time.h>

#include "minios/metrics_reporter.h"
#include "minios/utils.h"

namespace minios {

const char kRecoveryDurationMinutes[] = "Installer.Recovery.NbrDurationMinutes";
const char kRecoveryReason[] = "Installer.Recovery.Reason";
const char kStatefulEventsPath[] = "/stateful/.recovery_histograms";

// NOTE: The metrics should be renamed if the following settings are changed.
const int kRecoveryDurationMinutes_Buckets = 50;
const int kRecoveryDurationMinutes_MAX = 10 * 24 * 60;  // 10 days
const int kRecoveryReasonCode_NBR = 200;
const int kRecoveryReasonCode_MAX = 255;

MetricsReporter::MetricsReporter(
    ProcessManagerInterface* process_manager,
    std::unique_ptr<MetricsLibraryInterface> metrics_lib)
    : process_manager_(process_manager) {
  if (metrics_lib)
    metrics_lib_ = std::move(metrics_lib);
  else
    metrics_lib_ = std::make_unique<MetricsLibrary>();

  metrics_lib_->Init();
}

void MetricsReporter::RecordNBRStart() {
  start_time_ = base::Time::Now();
}

void MetricsReporter::ReportNBRComplete() {
  if (!MountStatefulPartition(process_manager_)) {
    PLOG(WARNING) << "Stateful mounting failed, skipping metrics reporting.";
    return;
  }

  metrics_lib_->SetOutputFile(kStatefulEventsPath);
  // Report recovery reason code.
  metrics_lib_->SendEnumToUMA(kRecoveryReason, kRecoveryReasonCode_NBR,
                              kRecoveryReasonCode_MAX);
  // Report duration.
  base::TimeDelta duration = base::Time::Now() - start_time_;
  metrics_lib_->SendToUMA(kRecoveryDurationMinutes, duration.InMinutes(),
                          /*min=*/0, kRecoveryDurationMinutes_MAX,
                          kRecoveryDurationMinutes_Buckets);
}

}  // namespace minios
