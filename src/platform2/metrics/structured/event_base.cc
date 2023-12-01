// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "metrics/structured/event_base.h"

#include "metrics/structured/recorder_singleton.h"

#include <base/logging.h>
#include <base/notreached.h>
#include <algorithm>

namespace metrics {
namespace structured {

EventBase::EventBase(uint64_t event_name_hash,
                     uint64_t project_name_hash,
                     IdType id_type,
                     StructuredEventProto_EventType event_type)
    : event_name_hash_(event_name_hash),
      project_name_hash_(project_name_hash),
      id_type_(id_type),
      event_type_(event_type) {}
EventBase::EventBase(const EventBase& other) = default;
EventBase::~EventBase() = default;

EventBase::Metric::Metric(uint64_t name_hash, MetricType type)
    : name_hash(name_hash), type(type) {}
EventBase::Metric::~Metric() = default;

bool EventBase::Record() {
  return RecorderSingleton::GetInstance()->GetRecorder()->Record(*this);
}

void EventBase::AddHmacMetric(uint64_t name_hash, const std::string& value) {
  Metric metric(name_hash, MetricType::kHmac);
  metric.hmac_value = value;
  metrics_.push_back(metric);
}

void EventBase::AddIntMetric(uint64_t name_hash, int64_t value) {
  Metric metric(name_hash, MetricType::kInt);
  metric.int_value = value;
  metrics_.push_back(metric);
}

void EventBase::AddRawStringMetric(uint64_t name_hash,
                                   const std::string& value) {
  Metric metric(name_hash, MetricType::kRawString);
  metric.string_value = value;
  metrics_.push_back(metric);
}

void EventBase::AddDoubleMetric(uint64_t name_hash, double value) {
  Metric metric(name_hash, MetricType::kDouble);
  metric.double_value = value;
  metrics_.push_back(metric);
}

void EventBase::AddIntArrayMetric(uint64_t name_hash,
                                  const std::vector<int64_t>& value,
                                  size_t max_length) {
  CHECK(value.size() <= max_length)
      << "Metric: " << name_hash << " array length larger then max ("
      << value.size() << " > " << max_length << ")";

  size_t size = std::min(max_length, value.size());
  Metric metric(name_hash, MetricType::kIntArray);
  metric.int_array_value = std::vector(value.begin(), value.begin() + size);
  metrics_.push_back(metric);
}

std::string EventBase::GetHmacMetricForTest(uint64_t name_hash) const {
  for (const auto& metric : metrics_) {
    if (metric.name_hash == name_hash) {
      return metric.hmac_value;
    }
  }
  NOTREACHED() << "Failed to get metric value. Invalid name hash " << name_hash;
  return "";
}

int64_t EventBase::GetIntMetricForTest(uint64_t name_hash) const {
  for (const auto& metric : metrics_) {
    if (metric.name_hash == name_hash) {
      return metric.int_value;
    }
  }
  NOTREACHED() << "Failed to get metric value. Invalid name hash " << name_hash;
  return 0;
}

std::string EventBase::GetRawStringMetricForTest(uint64_t name_hash) const {
  for (const auto& metric : metrics_) {
    if (metric.name_hash == name_hash) {
      return metric.string_value;
    }
  }
  NOTREACHED() << "Failed to get metric value. Invalid name hash " << name_hash;
  return "";
}

double EventBase::GetDoubleMetricForTest(uint64_t name_hash) const {
  for (const auto& metric : metrics_) {
    if (metric.name_hash == name_hash) {
      return metric.double_value;
    }
  }
  NOTREACHED() << "Failed to get metric value. Invalid name hash " << name_hash;
  return 0.0;
}

std::vector<int64_t> EventBase::GetIntArrayMetricForTest(
    uint64_t name_hash) const {
  for (const auto& metric : metrics_) {
    if (metric.name_hash == name_hash) {
      return metric.int_array_value;
    }
  }
  NOTREACHED() << "Failed to get metric value. Invalid name hash " << name_hash;
  return {};
}

}  // namespace structured
}  // namespace metrics
