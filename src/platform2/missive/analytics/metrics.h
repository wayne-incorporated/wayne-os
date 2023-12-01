// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_ANALYTICS_METRICS_H_
#define MISSIVE_ANALYTICS_METRICS_H_

#include <string>
#include <type_traits>

#include <base/memory/scoped_refptr.h>
#include <base/task/sequenced_task_runner.h>
#include <metrics/metrics_library.h>

namespace reporting::analytics {

// Provides access to `MetricsLibrary`. Guarantees that all calls to Send*ToUMA
// happen on the same task sequence.
//
// To use this class, call its Send*ToUMA methods just like `MetricsLibrary`:
//
//   Metrics::SendToUMA(....);
//   Metrics::SendLinearToUMA(....);
class Metrics {
 public:
  class TestEnvironment;

  Metrics() = delete;
  Metrics(const Metrics&) = delete;
  Metrics& operator=(const Metrics&) = delete;
  // Metrics should never be instantiated, no matter what.
  virtual ~Metrics() = 0;

  // Initialize the metrics instance.
  static void Initialize();

  // Proxy of `MetricsLibraryInterface::SendBoolToUMA`.
  static bool SendBoolToUMA(const std::string& name, bool sample);

  // Proxy of `MetricsLibraryInterface::SendEnumToUMA`.
  static bool SendEnumToUMA(const std::string& name,
                            int sample,
                            int exclusive_max);

  // A convenient wrapper of `SendEnumToUMA` that accepts an enum type directly.
  // Note that its behavior is different from
  // `MetricsLibraryInterface::SendEnumToUMA(const std::string& name, T
  // sample)`, where `T::kMaxValue` is an inclusive max (i.e., sample can equal
  // `T::kMaxValue`), whereas here sample can only be smaller than
  // `T::kMaxValue`.
  template <typename T>
  static bool SendEnumToUMA(const std::string& name,
                            T sample,
                            T exclusive_max = T::kMaxValue) {
    static_assert(std::is_enum_v<T>, "T is not an enum.");
    DCHECK_LT(static_cast<int>(sample), static_cast<int>(exclusive_max));
    return SendEnumToUMA(name, static_cast<int>(sample),
                         static_cast<int>(exclusive_max));
  }

  // Proxy of `MetricsLibraryInterface::SendPercentageToUMA`.
  static bool SendPercentageToUMA(const std::string& name, int sample);

  // Proxy of `MetricsLibraryInterface::SendLinearToUMA`.
  static bool SendLinearToUMA(const std::string& name, int sample, int max);

  // Proxy of `MetricsLibraryInterface::SendSparseToUMA`.
  static bool SendSparseToUMA(const std::string& name, int sample);

  // Proxy of `MetricsLibraryInterface::SendToUMA`.
  static bool SendToUMA(
      const std::string& name, int sample, int min, int max, int nbuckets);

  // Add new proxy methods here when you need to use
  // `MetricsLibrary::Send*ToUMA` methods that are not proxied above.

 private:
  friend class TestEnvironment;

  // Sends data to UMA.
  template <typename FuncType, typename... ArgTypes>
  static bool PostUMATask(FuncType send_to_uma_func, ArgTypes... args);

  // Get reference to the metrics library pointer for testing.
  static MetricsLibraryInterface*& GetMetricsLibraryForTest();
  // Get reference to the sequence task runner for testing.
  static scoped_refptr<base::SequencedTaskRunner>&
  GetMetricsTaskRunnerForTest();
};
}  // namespace reporting::analytics

#endif  // MISSIVE_ANALYTICS_METRICS_H_
