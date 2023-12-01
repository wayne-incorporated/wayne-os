// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_REQUEST_METRICS_H_
#define ML_REQUEST_METRICS_H_

#include <ctime>
#include <memory>
#include <string>

#include <base/check.h>
#include <metrics/metrics_library.h>

#include "metrics/timer.h"
#include "ml/util.h"

namespace ml {

// Performs UMA metrics logging for model loading (LoadBuiltinModel or
// LoadFlatBufferModel), CreateGraphExecutor and Execute. Metrics includes
// events(enumerators defined by RequestEventEnum), memory_usage, and cpu_time.
// RequestEventEnum is an enum class which defines different events for some
// specific actions, currently we reuse the enum classes defined in mojoms. The
// enum class generally contains an OK and several different Errors, besides,
// there should be a kMax which shares the value of the highest enumerator.
class RequestMetrics {
 public:
  // Creates a RequestMetrics with the specified model and request names.
  // Records UMA metrics named with the prefix
  // "MachineLearningService.`model_name`.`request_name`."
  RequestMetrics(const std::string& model_name,
                 const std::string& request_name);
  RequestMetrics(const RequestMetrics&) = delete;
  RequestMetrics& operator=(const RequestMetrics&) = delete;

  // Logs (to UMA) the specified `event` associated with this request.
  template <class RequestEventEnum>
  void RecordRequestEvent(RequestEventEnum event);

  // When you want to record metrics of some action, call Start func at the
  // beginning of it.
  void StartRecordingPerformanceMetrics();

  // Send performance metrics(memory_usage, cpu_time) to UMA
  // This would usually be called only if the action completes successfully.
  void FinishRecordingPerformanceMetrics();

 private:
  enum class Status {
    kNotStarted = 0,
    kRecording = 1,
    kEventSent = 2,
    kFinished = 3
  };

  MetricsLibrary metrics_library_;

  const std::string name_base_;
  std::clock_t initial_cpu_clock_;
  int64_t initial_memory_;

  // The `status_` serves as a safe guard to ensure the correct usage of the
  // objects of this class, specifically,
  // 1. `status_` is initialized to `kNotStarted` at construction.
  // 2. `StartRecordingPerformanceMetrics()` must be called when
  // `status_=kNotStarted`. And it sets `status_` to `kRecording`.
  // 3. `RecordRequestEvent()` must be called when `status_=kRecording` or
  // `status_=kFinished`, and it sets `status_` to `kEventSent`.
  // 4. `FinishRecordingPerformanceMetrics()` must be called when
  // `status_=kRecording` and it sets `status_` to `kEventFinished`.
  Status status_;
};

// UMA metric names:
constexpr char kGlobalMetricsPrefix[] = "MachineLearningService.";
constexpr char kEventSuffix[] = ".Event";
constexpr char kTotalMemoryDeltaSuffix[] = ".TotalMemoryDeltaKb";
constexpr char kCpuTimeSuffix[] = ".CpuTimeMicrosec";

// UMA histogram ranges:
constexpr int kMemoryDeltaMinKb = 1;         // 1 KB
constexpr int kMemoryDeltaMaxKb = 10000000;  // 10 GB
constexpr int kMemoryDeltaBuckets = 100;
constexpr int kCpuTimeMinMicrosec = 1;           // 1 μs
constexpr int kCpuTimeMaxMicrosec = 1800000000;  // 30 min
constexpr int kCpuTimeBuckets = 100;

template <class RequestEventEnum>
void RequestMetrics::RecordRequestEvent(RequestEventEnum event) {
  DCHECK(status_ == Status::kRecording || status_ == Status::kFinished);
  metrics_library_.SendEnumToUMA(
      name_base_ + kEventSuffix, static_cast<int>(event),
      static_cast<int>(RequestEventEnum::kMaxValue) + 1);
  status_ = Status::kEventSent;
}

// Records a generic model specification error event during a model loading
// (LoadBuiltinModel or LoadFlatBufferModel) request.
void RecordModelSpecificationErrorEvent();

// Multiprocess related errors.
enum class ProcessError {
  kSpawnWorkerProcessFailed = 0,
  kChangeEuidToMlServiceDBusFailed = 1,
  kChangeEuidBackToRootFailed = 2,
  kGetWorkerProcessMemoryUsageFailed = 3,
  kReapWorkerProcessMaxNumOfRetrialsExceeded = 4,
  kMaxValue = kReapWorkerProcessMaxNumOfRetrialsExceeded,
};

// Records Multiprocess related errors.
void RecordProcessErrorEvent(ProcessError error);

// Records the exit status of worker process.
void RecordWorkerProcessExitStatus(int status);

// Records the `errno` when waitpid failed in reaping worker processes.
void RecordReapWorkerProcessErrno(int error_number);

}  // namespace ml

#endif  // ML_REQUEST_METRICS_H_
