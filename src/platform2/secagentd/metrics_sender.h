// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SECAGENTD_METRICS_SENDER_H_
#define SECAGENTD_METRICS_SENDER_H_

#include <algorithm>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/functional/callback_forward.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/no_destructor.h"
#include "base/strings/strcat.h"
#include "base/task/task_runner.h"
#include "base/task/thread_pool.h"
#include "base/timer/timer.h"
#include "metrics/metrics_library.h"

namespace secagentd {
namespace testing {
class MetricsSenderTestFixture;
}  // namespace testing
namespace metrics {

using MetricsMap = std::unordered_map<std::string, int>;

static constexpr auto kMetricNamePrefix = "ChromeOS.Secagentd.";
static constexpr int kMaxMapValue = 256;
// Matches the time at which the metrics file is flushed (30s).
static constexpr int kBatchTimer = 30;

template <class E>
struct EnumMetric {
  const char* name;
  using Enum = E;
};

enum class Policy {
  kChecked,
  kEnabled,
  kMaxValue = kEnabled,
};

static constexpr EnumMetric<Policy> kPolicy = {.name = "Policy"};

enum class BpfAttachResult {
  kSuccess,
  kErrorOpen,
  kErrorLoad,
  kErrorAttach,
  kErrorRingBuffer,
  kMaxValue = kErrorRingBuffer,
};

static constexpr EnumMetric<BpfAttachResult> kNetworkBpfAttach = {
    .name = "Bpf.Network.AttachResult"};

static constexpr EnumMetric<BpfAttachResult> kProcessBpfAttach = {
    .name = "Bpf.Process.AttachResult"};

// This should always follow the missive status code.
// https://chromium.googlesource.com/chromiumos/platform2/+/6142bdcb70dc0987f9234c2294660f798d5df05a/missive/util/status.h#26
enum class SendMessage {
  kSuccess,
  kCancelled,
  kUnknown,
  kInvalidArgument,
  kDeadlineExceeded,
  kNotFound,
  kAlreadyExists,
  kPermissionDenied,
  kResourceExhausted,
  kFailedPrecondition,
  kAborted,
  kOutOfRange,
  kUnimplemetned,
  kInternal,
  kUnavailable,
  kDataLoss,
  kUnauthenticated,
  // The value should always be kept last.
  kMaxValue = kUnauthenticated,
};

static constexpr EnumMetric<SendMessage> kSendMessage = {
    .name = "SendMessageResult"};

enum class CrosBootmode {
  kSuccess,
  kValueNotSet,
  kUnavailable,
  kFailedRetrieval,
  kMaxValue = kFailedRetrieval,
};

static constexpr EnumMetric<CrosBootmode> kCrosBootmode = {.name =
                                                               "Bootmode.Cros"};

enum class UefiBootmode {
  kSuccess,
  kFileNotFound,
  kFailedToReadBootParams,
  kBootParamInvalidSize,
  kMaxValue = kBootParamInvalidSize,
};

static constexpr EnumMetric<UefiBootmode> kUefiBootmode = {.name =
                                                               "Bootmode.Uefi"};

enum class Tpm {
  kSuccess,
  kValueNotSet,
  kUnavailable,
  kFailedRetrieval,
  kMaxValue = kFailedRetrieval,
};

static constexpr EnumMetric<Tpm> kTpm = {.name = "Tpm"};

enum class Cache {
  kCacheHit,
  kCacheMiss,
  kProcfsFilled,
  kMaxValue = kProcfsFilled,
};

static constexpr EnumMetric<Cache> kCache = {.name = "Cache"};

constexpr char kCacheFullness[] = "CacheFullness";

enum class ProcessEvent {
  kFullEvent,
  kSpawnPidNotInCache,
  kProcessPidNotInCache,
  kParentPidNotInCache,
  kParentStillAlive,
  kMaxValue = kParentStillAlive,
};

static constexpr EnumMetric<ProcessEvent> kExecEvent = {
    .name = "Process.ExecEvent"};
static constexpr EnumMetric<ProcessEvent> kTerminateEvent = {
    .name = "Process.TerminateEvent"};
}  // namespace metrics

// Class for sending UMA metrics. Expected to be accessed as a Singleton via
// MetricsSender::GetInstance().
class MetricsSender {
 public:
  static MetricsSender& GetInstance();

  // Starts job to set up timer.
  void InitBatchedMetrics();

  // Send a metrics::EnumMetric sample to UMA. Synchronously calls into
  // MetricsLibrary.
  // Warning: Not safe for use in hot paths. Limit usage to infrequent events
  // (such as during daemon initialization).
  template <typename M>
  bool SendEnumMetricToUMA(M metric, typename M::Enum sample) {
    return metrics_library_->SendEnumToUMA(
        base::StrCat({metrics::kMetricNamePrefix, metric.name}), sample);
  }

  // Same as SendEnumMetricToUMA except sends percentage instead.
  bool SendPercentageMetricToUMA(std::string_view name, int sample) {
    return metrics_library_->SendPercentageToUMA(
        base::StrCat({metrics::kMetricNamePrefix, name}), sample);
  }

  // Creates a key with the given metric sample pair and increments the map
  // value by one.
  template <typename M>
  void IncrementBatchedMetric(M metric, typename M::Enum sample) {
    int sample_val = static_cast<int>(sample);
    // The key is name and sample separated by a colon.
    std::string key =
        base::StrCat({metric.name, ":", std::to_string(sample_val)});
    if (exclusive_max_map_.find(metric.name) == exclusive_max_map_.end()) {
      LOG(ERROR) << "Key not found in exclusive_max_map. Key = " << metric.name;
      return;
    }
    auto success_value = success_value_map_.find(metric.name);
    if (success_value == success_value_map_.end()) {
      LOG(ERROR) << "Key not found in success_value_map. Key = " << metric.name;
      return;
    }
    batch_count_map_[key]++;

    // Trigger a flush if count is high and not success value.
    if (batch_count_map_[key] >= metrics::kMaxMapValue &&
        sample_val != success_value->second) {
      Flush();
    }
  }

  void SetMetricsLibraryForTesting(
      std::unique_ptr<MetricsLibraryInterface> metrics_library) {
    metrics_library_ = std::move(metrics_library);
  }

  // Registers the given callback that will be sent every
  // 30 seconds by the flush timer.
  void RegisterMetricOnFlushCallback(base::RepeatingCallback<void()> cb);

 private:
  friend class base::NoDestructor<MetricsSender>;
  friend class testing::MetricsSenderTestFixture;

  // Sends all metrics contained in the metrics map.
  void SendBatchedMetricsToUMA(metrics::MetricsMap map_copy);

  // Starts job for SendMetricsToUMA and clears metrics_map_.
  void Flush();

  // Starts the batch timer using task_runner_.
  void StartBatchTimer();

  // Allow calling the private test-only constructor without befriending
  // unique_ptr.
  template <typename... Args>
  static std::unique_ptr<MetricsSender> CreateForTesting(Args&&... args) {
    return base::WrapUnique(new MetricsSender(std::forward<Args>(args)...));
  }

  MetricsSender();
  explicit MetricsSender(
      std::unique_ptr<MetricsLibraryInterface> metrics_library);

  base::WeakPtrFactory<MetricsSender> weak_ptr_factory_;
  base::RepeatingTimer flush_batched_metrics_timer_;
  scoped_refptr<base::SequencedTaskRunner> task_runner_ =
      base::ThreadPool::CreateSequencedTaskRunner({});
  std::unique_ptr<MetricsLibraryInterface> metrics_library_;
  std::vector<base::RepeatingCallback<void()>> metric_callbacks_;
  metrics::MetricsMap batch_count_map_;
  const metrics::MetricsMap exclusive_max_map_ = {
      {metrics::kSendMessage.name,
       static_cast<int>(metrics::SendMessage::kMaxValue) + 1},
      {metrics::kCache.name, static_cast<int>(metrics::Cache::kMaxValue) + 1},
      {metrics::kExecEvent.name,
       static_cast<int>(metrics::ProcessEvent::kMaxValue) + 1},
      {metrics::kTerminateEvent.name,
       static_cast<int>(metrics::ProcessEvent::kMaxValue) + 1}};
  const metrics::MetricsMap success_value_map_ = {
      {metrics::kSendMessage.name, 0},
      {metrics::kCache.name, 0},
      {metrics::kExecEvent.name, 0},
      {metrics::kTerminateEvent.name, 0}};
};
}  // namespace secagentd

#endif  // SECAGENTD_METRICS_SENDER_H_
