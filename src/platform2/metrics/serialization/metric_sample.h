// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_SERIALIZATION_METRIC_SAMPLE_H_
#define METRICS_SERIALIZATION_METRIC_SAMPLE_H_

#include <string>

#include "base/gtest_prod_util.h"

namespace metrics {

// This class is used by libmetrics (ChromeOS) to serialize
// and deserialize measurements to send them to a metrics sending service.
// It is meant to be a simple container with serialization functions.
class MetricSample {
 public:
  // Types of metric sample used.
  enum SampleType {
    INVALID,
    CRASH,
    HISTOGRAM,
    LINEAR_HISTOGRAM,
    SPARSE_HISTOGRAM,
    USER_ACTION,
  };

  // Constructs an invalid sample. Use the factory functions below to create
  // samples carrying actual data.
  MetricSample() {}
  ~MetricSample() = default;

  // Allow copy and move construction. Assignment is not available because all
  // data members are constant.
  MetricSample(const MetricSample& other) = default;
  MetricSample(MetricSample&& other) = default;

  // Returns true if the sample is valid (can be serialized without ambiguity).
  //
  // This function should be used to filter bad samples before serializing them.
  bool IsValid() const;

  // Getters for type and name. All types of metrics have these so we do not
  // need to check the type.
  SampleType type() const { return type_; }
  const std::string& name() const { return name_; }

  // Getters for sample, min, max, bucket_count, num_samples.
  // Check the metric type to make sure the request make sense. (ex: a crash
  // sample does not have a bucket_count so we crash if we call bucket_count()
  // on it.)
  int sample() const;
  int min() const;
  int max() const;
  int bucket_count() const;
  int num_samples() const;

  // Returns a serialized version of the sample.
  //
  // The serialized message for each type is:
  // crash: crash\0|name_|\0
  // user action: useraction\0|name_|\0
  // histogram: histogram\0|name_| |sample_| |min_| |max_| |bucket_count_|\0
  // sparsehistogram: sparsehistogram\0|name_| |sample_|\0
  // linearhistogram: linearhistogram\0|name_| |sample_| |max_|\0
  std::string ToString() const;

  // Builds a crash sample.
  static MetricSample CrashSample(const std::string& crash_name);

  // Builds a histogram sample.
  // Chrome doesn't support repeated samples yet, non-one counts
  // can only be used (outside of unit tests) when
  // conditional compile flag USE_METRICS_UPLOADER is 1.
  static MetricSample HistogramSample(const std::string& histogram_name,
                                      int sample,
                                      int min,
                                      int max,
                                      int bucket_count,
                                      int num_samples = 1);
  // Deserializes a histogram sample.
  static MetricSample ParseHistogram(const std::string& serialized);

  // Builds a sparse histogram sample.
  static MetricSample SparseHistogramSample(const std::string& histogram_name,
                                            int sample);
  // Deserializes a sparse histogram sample.
  static MetricSample ParseSparseHistogram(const std::string& serialized);

  // Builds a linear histogram sample.
  static MetricSample LinearHistogramSample(const std::string& histogram_name,
                                            int sample,
                                            int max);
  // Deserializes a linear histogram sample.
  static MetricSample ParseLinearHistogram(const std::string& serialized);

  // Builds a user action sample.
  static MetricSample UserActionSample(const std::string& action_name);

  // Returns true if sample and this object represent the same sample (type,
  // name, sample, min, max, bucket_count match).
  bool IsEqual(const MetricSample& sample) const;

 private:
  MetricSample(SampleType sample_type,
               const std::string& metric_name,
               const int sample,
               const int min,
               const int max,
               const int bucket_count,
               const int num_samples = 1);

  const SampleType type_ = INVALID;
  const std::string name_;
  const int sample_ = 0;
  const int min_ = 0;
  const int max_ = 0;
  const int bucket_count_ = 0;
  const int num_samples_ = 0;
};

}  // namespace metrics

#endif  // METRICS_SERIALIZATION_METRIC_SAMPLE_H_
