// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_FAKE_METRICS_LIBRARY_H_
#define METRICS_FAKE_METRICS_LIBRARY_H_

#include <limits>
#include <map>
#include <string>
#include <vector>

#include "metrics/metrics_library.h"

// FakeMetricsLibrary provides a fake MetricsLibraryInterface implementation
// that keeps track of calls to Send*ToUMA and the values sent. It provides
// additional getters allowing tests to examine the results. The implementation
// is intentionally minimal, please extend as needed.
class FakeMetricsLibrary : public MetricsLibraryInterface {
 public:
  FakeMetricsLibrary() = default;
  ~FakeMetricsLibrary() = default;
  FakeMetricsLibrary(const FakeMetricsLibrary&) = delete;
  FakeMetricsLibrary& operator=(const FakeMetricsLibrary&) = delete;

  // MetricsLibraryInterface
  void Init() override;
  bool AreMetricsEnabled() override;
  bool IsAppSyncEnabled() override;
  bool IsGuestMode() override;
  bool SendToUMA(const std::string& name,
                 int sample,
                 int min,
                 int max,
                 int nbuckets) override;
  bool SendEnumToUMA(const std::string& name,
                     int sample,
                     int exclusive_max) override;
  bool SendRepeatedEnumToUMA(const std::string& name,
                             int sample,
                             int exclusive_max,
                             int num_samples) override;
  bool SendLinearToUMA(const std::string& name, int sample, int max) override;
  bool SendPercentageToUMA(const std::string& name, int sample) override;
  bool SendBoolToUMA(const std::string& name, bool sample) override;
  bool SendSparseToUMA(const std::string& name, int sample) override;

  // The following MetricsLibraryInterface methods are not implemented:
  bool SendUserActionToUMA(const std::string& action) override;
  bool SendCrashToUMA(const char* crash_kind) override;
  bool SendCrosEventToUMA(const std::string& event) override;
#if USE_METRICS_UPLOADER
  bool SendRepeatedToUMA(const std::string& name,
                         int sample,
                         int min,
                         int max,
                         int nbuckets,
                         int num_samples) override;
#endif
  void SetOutputFile(const std::string& output_file) override;

  // Test getters

  // Get all calls to the given metric.
  std::vector<int> GetCalls(const std::string& name);

  // Return the number of calls to the given metric.
  size_t NumCalls(const std::string& name);

  // Get the value of the most recent call to the given metric. Returns kInvalid
  // if no metric was recorded.
  int GetLast(const std::string& name);

  // Clear all metrics stored by the FakeMetricsLibrary.
  void Clear();

  static constexpr int kInvalid = std::numeric_limits<int>::min();

 private:
  std::map<std::string, std::vector<int>> metrics_;
};

#endif  // METRICS_FAKE_METRICS_LIBRARY_H_
