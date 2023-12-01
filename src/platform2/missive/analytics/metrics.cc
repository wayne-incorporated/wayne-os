// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/analytics/metrics.h"

#include <string>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/scoped_refptr.h>
#include <base/no_destructor.h>
#include <base/task/sequenced_task_runner.h>
#include <base/task/thread_pool.h>
#include <metrics/metrics_library.h>

namespace reporting::analytics {

namespace {
// The only `MetricsLibrary` instance. In production code, it never changes
// once set.
MetricsLibraryInterface* g_metrics_library = nullptr;

// The task runner on which metrics sends data. In production code, it never
// changes once set.
scoped_refptr<base::SequencedTaskRunner>& metrics_task_runner() {
  static base::NoDestructor<scoped_refptr<base::SequencedTaskRunner>>
      task_runner;
  return *task_runner;
}
}  // namespace

// static
void Metrics::Initialize() {
  if (metrics_task_runner()) {
    LOG(ERROR) << "Metrics already initialized or scheduled to be initialized. "
                  "skip initialization.";
    return;
  }
  metrics_task_runner() = base::ThreadPool::CreateSequencedTaskRunner(
      {base::MayBlock(), base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN});
  metrics_task_runner()->PostTask(FROM_HERE, base::BindOnce([]() {
                                    g_metrics_library = new MetricsLibrary();
                                  }));
}

// static
template <typename FuncType, typename... ArgTypes>
bool Metrics::PostUMATask(FuncType send_to_uma_func, ArgTypes... args) {
  if (!metrics_task_runner()) {
    LOG(ERROR) << "Task runner for metrics is not up. Not sending data to UMA.";
    return false;
  }

  return metrics_task_runner()->PostTask(
      FROM_HERE,
      // Wrap send_to_uma_func with a void-return type lambda.
      base::BindOnce(
          [](FuncType send_to_uma_func, ArgTypes... args) -> void {
            if (!g_metrics_library) {
              // In theory, this block is only reachable in test.
              LOG(ERROR)
                  << "Metrics library not initialized. Skip sending to UMA.";
              return;
            }
            const bool success =
                (g_metrics_library->*send_to_uma_func)(args...);
            LOG_IF(WARNING, !success) << "Send to UMA failed.";
          },
          send_to_uma_func, args...));
}

// static
bool Metrics::SendBoolToUMA(const std::string& name, bool sample) {
  return PostUMATask(&MetricsLibraryInterface::SendBoolToUMA, name, sample);
}

// static
bool Metrics::SendSparseToUMA(const std::string& name, int sample) {
  return PostUMATask(&MetricsLibraryInterface::SendSparseToUMA, name, sample);
}

// static
bool Metrics::SendEnumToUMA(const std::string& name,
                            int sample,
                            int exclusive_max) {
  return PostUMATask(static_cast<bool (MetricsLibraryInterface::*)(
                         const std::string&, int, int)>(
                         &MetricsLibraryInterface::SendEnumToUMA),
                     name, sample, exclusive_max);
}

// static
bool Metrics::SendPercentageToUMA(const std::string& name, int sample) {
  return PostUMATask(&MetricsLibraryInterface::SendPercentageToUMA, name,
                     sample);
}

// static
bool Metrics::SendLinearToUMA(const std::string& name, int sample, int max) {
  return PostUMATask(&MetricsLibraryInterface::SendLinearToUMA, name, sample,
                     max);
}

// static
bool Metrics::SendToUMA(
    const std::string& name, int sample, int min, int max, int nbuckets) {
  return PostUMATask(&MetricsLibraryInterface::SendToUMA, name, sample, min,
                     max, nbuckets);
}

// static
MetricsLibraryInterface*& Metrics::GetMetricsLibraryForTest() {
  return g_metrics_library;
}

// static
scoped_refptr<base::SequencedTaskRunner>&
Metrics::GetMetricsTaskRunnerForTest() {
  return metrics_task_runner();
}

}  // namespace reporting::analytics
