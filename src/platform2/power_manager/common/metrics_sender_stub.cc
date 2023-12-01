// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/common/metrics_sender_stub.h"

#include <base/logging.h>
#include <base/strings/stringprintf.h>

namespace power_manager {

MetricsSenderStub::Metric::Metric()
    : type(Type::EXPONENTIAL),
      sample(0),
      min(0),  // NOLINT(build/include_what_you_use)
      max(0),  // NOLINT(build/include_what_you_use)
      num_buckets(0) {}

// static
MetricsSenderStub::Metric MetricsSenderStub::Metric::CreateExp(
    const std::string& name, int sample, int min, int max, int num_buckets) {
  Metric metric;
  metric.name = name;
  metric.type = Type::EXPONENTIAL;
  metric.sample = sample;
  metric.min = min;
  metric.max = max;
  metric.num_buckets = num_buckets;
  return metric;
}

MetricsSenderStub::Metric MetricsSenderStub::Metric::CreateEnum(
    const std::string& name, int sample, int max) {
  Metric metric;
  metric.name = name;
  metric.type = Type::ENUMERATION;
  metric.sample = sample;
  metric.max = max;
  return metric;
}

std::string MetricsSenderStub::Metric::ToString() const {
  return base::StringPrintf(
      "name=%s,type=%d,sample=%d,min=%d,max=%d,num_buckets=%d", name.c_str(),
      static_cast<int>(type), sample, min, max, num_buckets);
}

MetricsSenderStub::MetricsSenderStub() {
  MetricsSenderInterface::SetInstance(this);
}

MetricsSenderStub::~MetricsSenderStub() {
  MetricsSenderInterface::SetInstance(nullptr);
}

std::string MetricsSenderStub::GetMetric(size_t i) const {
  return metrics_.size() > i ? metrics_[i].ToString() : std::string();
}

bool MetricsSenderStub::SendMetric(
    const std::string& name, int sample, int min, int max, int num_buckets) {
  metrics_.push_back(Metric::CreateExp(name, sample, min, max, num_buckets));
  return true;
}

bool MetricsSenderStub::SendEnumMetric(const std::string& name,
                                       int sample,
                                       int max) {
  metrics_.push_back(Metric::CreateEnum(name, sample, max));
  return true;
}

}  // namespace power_manager
