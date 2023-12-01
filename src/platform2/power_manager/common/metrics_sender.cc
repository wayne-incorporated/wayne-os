// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/common/metrics_sender.h"

#include <utility>

#include <base/check.h>
#include <base/logging.h>
#include <metrics/metrics_library.h>

namespace power_manager {

namespace {

// Singleton instance; weak pointer.
MetricsSenderInterface* instance_ = nullptr;

}  // namespace

// static
MetricsSenderInterface* MetricsSenderInterface::GetInstance() {
  return instance_;
}

// static
void MetricsSenderInterface::SetInstance(MetricsSenderInterface* instance) {
  CHECK((!!instance_) ^ (!!instance))
      << "Replacing live instance " << instance_ << " with " << instance;
  instance_ = instance;
}

MetricsSender::MetricsSender(MetricsLibraryInterface& metrics_lib)
    : metrics_lib_(&metrics_lib) {
  MetricsSenderInterface::SetInstance(this);
}

MetricsSender::~MetricsSender() {
  MetricsSenderInterface::SetInstance(nullptr);
}

bool MetricsSender::SendMetric(
    const std::string& name, int sample, int min, int max, int num_buckets) {
  VLOG(1) << "Sending metric " << name << " (sample=" << sample
          << " min=" << min << " max=" << max << " num_buckets=" << num_buckets
          << ")";

  // Chrome appears to silently drop histograms with too-large bucket counts.
  // Running into this warning is a good sign that SendEnumMetric() should be
  // used instead to get a bucket for each of the possible values instead of
  // exponentially-sized buckets.
  if (num_buckets > max - min + 2) {
    LOG(WARNING) << name << " using excessive bucket count " << num_buckets
                 << "; consider sending as enum instead";
  }

  // If the sample falls outside of the histogram's range, just let it end up in
  // the underflow or overflow bucket.
  if (!metrics_lib_->SendToUMA(name, sample, min, max, num_buckets)) {
    LOG(ERROR) << "Failed to send metric " << name;
    return false;
  }
  return true;
}

bool MetricsSender::SendEnumMetric(const std::string& name,
                                   int sample,
                                   int max) {
  VLOG(1) << "Sending enum metric " << name << " (sample=" << sample
          << " max=" << max << ")";

  if (sample > max) {
    LOG(WARNING) << name << " sample " << sample << " is greater than " << max;
    sample = max;
  }

  if (!metrics_lib_->SendEnumToUMA(name, sample, max)) {
    LOG(ERROR) << "Failed to send enum metric " << name;
    return false;
  }
  return true;
}

bool SendMetric(
    const std::string& name, int sample, int min, int max, int num_buckets) {
  MetricsSenderInterface* sender = MetricsSenderInterface::GetInstance();
  return sender ? sender->SendMetric(name, sample, min, max, num_buckets)
                : true;
}

bool SendEnumMetric(const std::string& name, int sample, int max) {
  MetricsSenderInterface* sender = MetricsSenderInterface::GetInstance();
  return sender ? sender->SendEnumMetric(name, sample, max) : true;
}

}  // namespace power_manager
