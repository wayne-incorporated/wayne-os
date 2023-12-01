// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_STRUCTURED_EVENT_BASE_H_
#define METRICS_STRUCTURED_EVENT_BASE_H_

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include <brillo/brillo_export.h>

#include "metrics/structured/proto/storage.pb.h"

namespace metrics {
namespace structured {

// A base class for generated structured metrics event objects. This class
// should not be used directly.
class BRILLO_EXPORT EventBase {
 public:
  EventBase(const EventBase& other);
  virtual ~EventBase();

  // Specifies the type of identifier attached to an event.
  enum class IdType {
    // Events are attached to a per-event (or per-project) id.
    kProjectId = 0,
    // Events are attached to the UMA client_id.
    kUmaId = 1,
    // Events are attached to no id.
    kUnidentified = 2,
  };

  // Specifies which value type a Metric object holds.
  enum class MetricType {
    kHmac = 0,
    kInt = 1,
    kRawString = 2,
    kDouble = 3,
    kIntArray = 4,
  };

  // Stores all information about a single metric: name hash, value, and a
  // specifier of the value type.
  struct Metric {
    Metric(uint64_t name_hash, MetricType type);
    ~Metric();

    // First 8 bytes of the MD5 hash of the metric name, as defined in
    // structured.xml. This is calculated by metrics/structured/codegen.py.
    uint64_t name_hash;
    MetricType type;

    // All possible value types a metric can take. Exactly one of these should
    // be set. If |hmac_value| is set (with |type| as MetricType::kHmac),
    // only the HMAC digest will be reported, so it is safe to put any value
    // here. If |string_value| is set (with |type| as MetricType::kRawString),
    // the unprocessed string will be reported.
    std::string hmac_value;
    int64_t int_value;
    std::string string_value;
    double double_value;
    std::vector<int64_t> int_array_value;
  };

  // Finalizes the event and sends it for recording. After this call, the event
  // is left in an invalid state and should not be used further. Returns false
  // if the event has failed to be recorded, eg. due to content.
  bool Record();

  std::vector<Metric> metrics() const { return metrics_; }

  uint64_t name_hash() const { return event_name_hash_; }

  uint64_t project_name_hash() const { return project_name_hash_; }

  IdType id_type() const { return id_type_; }

  StructuredEventProto_EventType event_type() const { return event_type_; }

 protected:
  EventBase(uint64_t event_name_hash,
            uint64_t project_name_hash,
            IdType id_type,
            StructuredEventProto_EventType event_type);

  void AddHmacMetric(uint64_t name_hash, const std::string& value);

  void AddIntMetric(uint64_t name_hash, int64_t value);

  void AddRawStringMetric(uint64_t name_hash, const std::string& value);

  void AddDoubleMetric(uint64_t name_hash, double value);

  void AddIntArrayMetric(uint64_t hash_name,
                         const std::vector<int64_t>& values,
                         size_t max_length);

  std::string GetHmacMetricForTest(uint64_t name_hash) const;

  int64_t GetIntMetricForTest(uint64_t name_hash) const;

  std::string GetRawStringMetricForTest(uint64_t name_hash) const;

  double GetDoubleMetricForTest(uint64_t name_hash) const;

  std::vector<int64_t> GetIntArrayMetricForTest(uint64_t name_hash) const;

 private:
  // First 8 bytes of the MD5 hash of the following string:
  //
  //   cros::{project_name}::{event_name}
  //
  // Where the project and event name are defined in structured.xml. This is
  // calculated by metrics/structured/codegen.py.
  uint64_t event_name_hash_;

  // First 8 bytes of the MD5 hash of this event's project's name, as defined
  // in structured.xml.
  uint64_t project_name_hash_;

  // See enum definition.
  IdType id_type_;

  // Specifies the type of an event, which determines how it is treated after
  // upload. See platform2/metrics/structured/proto/structured_data.proto
  // for more information.
  StructuredEventProto_EventType event_type_;

  std::vector<Metric> metrics_;
};

}  // namespace structured
}  // namespace metrics

#endif  // METRICS_STRUCTURED_EVENT_BASE_H_
