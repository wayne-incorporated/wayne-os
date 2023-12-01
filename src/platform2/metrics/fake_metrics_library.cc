// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "metrics/fake_metrics_library.h"

const int kMaxNumberOfSamples = 512;

void FakeMetricsLibrary::Init() {}

bool FakeMetricsLibrary::AreMetricsEnabled() {
  return true;
}

bool FakeMetricsLibrary::IsAppSyncEnabled() {
  return true;
}

bool FakeMetricsLibrary::IsGuestMode() {
  return false;
}

bool FakeMetricsLibrary::SendToUMA(
    const std::string& name, int sample, int min, int max, int nbuckets) {
  metrics_[name].push_back(sample);
  return true;
}

bool FakeMetricsLibrary::SendEnumToUMA(const std::string& name,
                                       int sample,
                                       int exclusive_max) {
  return SendRepeatedEnumToUMA(name, sample, exclusive_max, 1);
}

bool FakeMetricsLibrary::SendRepeatedEnumToUMA(const std::string& name,
                                               int sample,
                                               int exclusive_max,
                                               int num_samples) {
  if (num_samples >= kMaxNumberOfSamples) {
    return false;
  }

  std::vector<int> samples = std::vector<int>(num_samples, sample);
  auto arr = &metrics_[name];
  arr->insert(std::end(*arr), std::begin(samples), std::end(samples));
  return true;
}

bool FakeMetricsLibrary::SendLinearToUMA(const std::string& name,
                                         int sample,
                                         int max) {
  metrics_[name].push_back(sample);
  return true;
}

bool FakeMetricsLibrary::SendPercentageToUMA(const std::string& name,
                                             int sample) {
  metrics_[name].push_back(sample);
  return true;
}

bool FakeMetricsLibrary::SendBoolToUMA(const std::string& name, bool sample) {
  metrics_[name].push_back(sample ? 1 : 0);
  return true;
}

bool FakeMetricsLibrary::SendSparseToUMA(const std::string& name, int sample) {
  metrics_[name].push_back(sample);
  return true;
}

bool FakeMetricsLibrary::SendUserActionToUMA(const std::string& action) {
  return false;
}

bool FakeMetricsLibrary::SendCrashToUMA(const char* crash_kind) {
  return false;
}

bool FakeMetricsLibrary::SendCrosEventToUMA(const std::string& event) {
  return false;
}

#if USE_METRICS_UPLOADER
bool FakeMetricsLibrary::SendRepeatedToUMA(const std::string& name,
                                           int sample,
                                           int min,
                                           int max,
                                           int nbuckets,
                                           int num_samples) {
  return false;
}
#endif

void FakeMetricsLibrary::SetOutputFile(const std::string& output_file) {}

// Test Getters

std::vector<int> FakeMetricsLibrary::GetCalls(const std::string& name) {
  return metrics_[name];
}

size_t FakeMetricsLibrary::NumCalls(const std::string& name) {
  return GetCalls(name).size();
}

int FakeMetricsLibrary::GetLast(const std::string& name) {
  std::vector<int> calls = GetCalls(name);
  if (calls.empty()) {
    return kInvalid;
  }
  return calls.back();
}

void FakeMetricsLibrary::Clear() {
  metrics_.clear();
}
