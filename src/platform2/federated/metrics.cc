// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "federated/metrics.h"

#include <ctime>

#include <base/strings/stringprintf.h>

namespace federated {

namespace {
constexpr char kServiceEventHistogram[] = "FederatedService.ServiceEvent";
constexpr char kStorageEventHistogram[] = "FederatedService.StorageEvent";
constexpr char kClientEventHistogram[] = "FederatedService.%s.Event";
constexpr char kClientCpuTimeHistogram[] =
    "FederatedService.%s.CpuTimeMicrosec";

constexpr int kCpuTimeMinMicrosec = 1;           // 1 us
constexpr int kCpuTimeMaxMicrosec = 1800000000;  // 30 min
constexpr int kCpuTimeBuckets = 100;
}  // namespace

void Metrics::LogServiceEvent(ServiceEvent event) const {
  metrics_library_->SendEnumToUMA(kServiceEventHistogram, event);
}

void Metrics::LogStorageEvent(StorageEvent event) const {
  metrics_library_->SendEnumToUMA(kStorageEventHistogram, event);
}

void Metrics::LogClientEvent(const std::string& client_name,
                             ClientEvent event) const {
  metrics_library_->SendEnumToUMA(
      base::StringPrintf(kClientEventHistogram, client_name.c_str()), event);
}

void Metrics::LogExampleReceived(const std::string& client_name) const {
  LogClientEvent(client_name, ClientEvent::kExampleReceived);
}

ScopedMetricsRecorder Metrics::CreateScopedMetricsRecorder(
    const std::string& client_name) {
  return ScopedMetricsRecorder(client_name, metrics_library_.get());
}

// static:
Metrics* Metrics::GetInstance() {
  static base::NoDestructor<Metrics> instance;
  return instance.get();
}

Metrics::Metrics() : metrics_library_(new MetricsLibrary()) {}

Metrics::~Metrics() = default;

void ScopedMetricsRecorder::MarkSuccess() {
  success_ = true;
}

ScopedMetricsRecorder::ScopedMetricsRecorder(
    const std::string& client_name, MetricsLibraryInterface* metrics_library)
    : client_name_(client_name),
      initial_cpu_clock_(std::clock()),
      success_(false),
      metrics_library_(metrics_library) {
  DCHECK(initial_cpu_clock_ != static_cast<std::clock_t>(-1));
  DCHECK(metrics_library_ != nullptr);
}

ScopedMetricsRecorder::~ScopedMetricsRecorder() {
  if (success_) {
    const int64_t cpu_time_microsec = static_cast<int64_t>(
        (std::clock() - initial_cpu_clock_) * 1000000.0 / CLOCKS_PER_SEC);

    metrics_library_->SendToUMA(
        base::StringPrintf(kClientCpuTimeHistogram, client_name_.c_str()),
        cpu_time_microsec, kCpuTimeMinMicrosec, kCpuTimeMaxMicrosec,
        kCpuTimeBuckets);
  }
}

}  // namespace federated
