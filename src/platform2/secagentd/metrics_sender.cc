// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "secagentd/metrics_sender.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "base/functional/bind.h"
#include "base/functional/callback_forward.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/no_destructor.h"
#include "base/time/time.h"
#include "metrics/metrics_library.h"

namespace secagentd {

MetricsSender& MetricsSender::GetInstance() {
  static base::NoDestructor<MetricsSender> instance;
  return *instance;
}

void MetricsSender::InitBatchedMetrics() {
  flush_batched_metrics_timer_.Start(
      FROM_HERE, base::Seconds(metrics::kBatchTimer),
      base::BindRepeating(&MetricsSender::Flush, base::Unretained(this)));
}

void MetricsSender::Flush() {
  metrics::MetricsMap map_copy(batch_count_map_);
  batch_count_map_.clear();

  task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&MetricsSender::SendBatchedMetricsToUMA,
                                weak_ptr_factory_.GetWeakPtr(), map_copy));

  // Run registered callbacks.
  for (auto cb : metric_callbacks_) {
    cb.Run();
  }
}

void MetricsSender::SendBatchedMetricsToUMA(metrics::MetricsMap map_copy) {
  for (auto const& [key, val] : map_copy) {
    int pos = key.find_last_of(":");
    auto metric_name = key.substr(0, pos);
    auto sample = stoi(key.substr(pos + 1));
    auto it = exclusive_max_map_.find(metric_name.c_str());

    // If sample is success value divide by 100.
    int count = val;
    if (sample == success_value_map_.find(metric_name)->second) {
      count = (count + 100 - 1) / 100;
    }

    if (!metrics_library_->SendRepeatedEnumToUMA(
            base::StrCat({metrics::kMetricNamePrefix, metric_name}), sample,
            it->second, count)) {
      LOG(ERROR) << "Failed to send batched metrics for " << metric_name;
    }
  }
}

void MetricsSender::RegisterMetricOnFlushCallback(
    base::RepeatingCallback<void()> cb) {
  metric_callbacks_.push_back(std::move(cb));
}

MetricsSender::MetricsSender()
    : MetricsSender(std::make_unique<MetricsLibrary>()) {}

MetricsSender::MetricsSender(
    std::unique_ptr<MetricsLibraryInterface> metrics_library)
    : weak_ptr_factory_(this), metrics_library_(std::move(metrics_library)) {}

}  // namespace secagentd
