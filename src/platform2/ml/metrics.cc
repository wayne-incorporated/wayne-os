// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/metrics.h"

#include <algorithm>
#include <string>
#include <vector>

#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/system/sys_info.h>
#include <base/time/time.h>

#include "ml/process.h"
#include "ml/request_metrics.h"
#include "ml/util.h"

namespace ml {

namespace {

// UMA metric names:
constexpr char kCpuUsageMetricName[] =
    "MachineLearningService.CpuUsageMilliPercent";
constexpr char kMojoConnectionEventMetricName[] =
    "MachineLearningService.MojoConnectionEvent";
constexpr char kTotalMemoryMetricName[] =
    "MachineLearningService.TotalMemoryKb";
constexpr char kPeakTotalMemoryMetricName[] =
    "MachineLearningService.PeakTotalMemoryKb";
constexpr char kNumWorkerProcessMetricName[] =
    "MachineLearningService.NumWorkerProcess";

// UMA histogram ranges:
constexpr int kCpuUsageMinMilliPercent = 1;       // 0.001%
constexpr int kCpuUsageMaxMilliPercent = 100000;  // 100%
constexpr int kCpuUsageBuckets = 25;
constexpr int kMemoryUsageMinKb = 10;         // 10 KB
constexpr int kMemoryUsageMaxKb = 100000000;  // 100 GB
constexpr int kMemoryUsageBuckets = 100;
constexpr int kNumWorkerProcessMin = 0;
constexpr int kNumWorkerProcessMax = 1000;
constexpr int kNumWorkerProcessBuckets = 100;

// chromeos_metrics::CumulativeMetrics constants:
constexpr char kCumulativeMetricsBackingDir[] = "/var/lib/ml_service/metrics";
constexpr char kPeakTotalMemoryCumulativeStatName[] = "peak_total_memory_kb";

constexpr base::TimeDelta kCumulativeMetricsUpdatePeriod = base::Minutes(5);
constexpr base::TimeDelta kCumulativeMetricsReportPeriod = base::Days(1);

void RecordCumulativeMetrics(
    MetricsLibrary* const metrics_library,
    chromeos_metrics::CumulativeMetrics* const cumulative_metrics) {
  metrics_library->SendToUMA(
      kPeakTotalMemoryMetricName,
      cumulative_metrics->Get(kPeakTotalMemoryCumulativeStatName),
      kMemoryUsageMinKb, kMemoryUsageMaxKb, kMemoryUsageBuckets);
}

// Returns true if getting the RAM of control process succeeds. Otherwise
// returns false in which case the value of `total_mem_usage` should be
// ignored.
// Here we ignore the return status of getting worker processes's RAM usage
// because there may be a case that the worker process has disappeared but it
// has not been removed from Process::GetWorkerPidInfoMap(). We do not want this
// to block the overall metric report. In the future, we may implement some
// dedicated metrics to report such cases.
bool GetControlAndWorkerProcessMemoryUsage(size_t* total_mem_usage) {
  DCHECK(total_mem_usage != nullptr);
  *total_mem_usage = 0;
  MemoryUsage usage;
  // Collect RAM usage for worker processes.
  // Do not crash if `GetProcessMemoryUsage` fails for worker processes because
  // maybe some worker process terminates before it is unregistered.
  for (const auto& pid_info : Process::GetInstance()->GetWorkerPidInfoMap()) {
    if (GetProcessMemoryUsage(&usage, pid_info.first)) {
      *total_mem_usage += usage.VmRSSKb + usage.VmSwapKb;
    } else {
      RecordProcessErrorEvent(ProcessError::kGetWorkerProcessMemoryUsageFailed);
    }
  }
  // Collect RAM usage for control processes.
  if (GetProcessMemoryUsage(&usage)) {
    *total_mem_usage += usage.VmRSSKb + usage.VmSwapKb;
    return true;
  } else {
    return false;
  }
}

}  // namespace

Metrics::Metrics()
    : process_metrics_(base::ProcessMetrics::CreateCurrentProcessMetrics()) {}

void Metrics::StartCollectingProcessMetrics() {
  if (cumulative_metrics_) {
    LOG(WARNING) << "Multiple calls to StartCollectingProcessMetrics";
    return;
  }

  // Baseline the CPU usage counter in `process_metrics_` to be zero as of now.
  const double initial_cpu_usage =
      process_metrics_->GetPlatformIndependentCPUUsage();
  DCHECK_EQ(initial_cpu_usage, 0);

  cumulative_metrics_ = std::make_unique<chromeos_metrics::CumulativeMetrics>(
      base::FilePath(kCumulativeMetricsBackingDir),
      std::vector<std::string>{kPeakTotalMemoryCumulativeStatName},
      kCumulativeMetricsUpdatePeriod,
      base::BindRepeating(&Metrics::UpdateAndRecordMetrics,
                          base::Unretained(this),
                          true /*record_current_metrics*/),
      kCumulativeMetricsReportPeriod,
      base::BindRepeating(&RecordCumulativeMetrics,
                          base::Unretained(&metrics_library_)));
}

void Metrics::UpdateCumulativeMetricsNow() {
  if (!cumulative_metrics_) {
    return;
  }
  UpdateAndRecordMetrics(false /*record_current_metrics*/,
                         cumulative_metrics_.get());
}

void Metrics::UpdateAndRecordMetrics(
    const bool record_current_metrics,
    chromeos_metrics::CumulativeMetrics* const cumulative_metrics) {
  size_t usage = 0;
  if (!GetControlAndWorkerProcessMemoryUsage(&usage)) {
    LOG(DFATAL) << "Getting process memory usage failed";
    return;
  }

  // Update max memory stats.
  cumulative_metrics->Max(kPeakTotalMemoryCumulativeStatName,
                          static_cast<int64_t>(usage));

  if (record_current_metrics) {
    // Record CPU usage (units = milli-percent i.e. 0.001%):
    // First get the CPU usage of the control process.
    auto cpu_usage = process_metrics_->GetPlatformIndependentCPUUsage();
    // Then get the CPU usages of the worker processes.
    for (const auto& pid_info : Process::GetInstance()->GetWorkerPidInfoMap()) {
      cpu_usage +=
          pid_info.second.process_metrics->GetPlatformIndependentCPUUsage();
    }

    const int cpu_usage_milli_percent = static_cast<int>(
        1000. * cpu_usage / base::SysInfo::NumberOfProcessors());
    metrics_library_.SendToUMA(kCpuUsageMetricName, cpu_usage_milli_percent,
                               kCpuUsageMinMilliPercent,
                               kCpuUsageMaxMilliPercent, kCpuUsageBuckets);
    // Record memory usage:
    metrics_library_.SendToUMA(kTotalMemoryMetricName, usage, kMemoryUsageMinKb,
                               kMemoryUsageMaxKb, kMemoryUsageBuckets);

    // Record how many worker processes.
    metrics_library_.SendToUMA(
        kNumWorkerProcessMetricName,
        Process::GetInstance()->GetWorkerPidInfoMap().size(),
        kNumWorkerProcessMin, kNumWorkerProcessMax, kNumWorkerProcessBuckets);
  }
}

void Metrics::RecordMojoConnectionEvent(const MojoConnectionEvent event) {
  metrics_library_.SendEnumToUMA(kMojoConnectionEventMetricName, event);
}

}  // namespace ml
