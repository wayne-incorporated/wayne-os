// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "metrics/serialization/metric_sample.h"

#include <string>
#include <vector>

#include "base/logging.h"
#include "base/notreached.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/stringprintf.h"

#include <base/check_op.h>

namespace metrics {

MetricSample::MetricSample(MetricSample::SampleType sample_type,
                           const std::string& metric_name,
                           int sample,
                           int min,
                           int max,
                           int bucket_count,
                           int num_samples)
    : type_(sample_type),
      name_(metric_name),
      sample_(sample),
      min_(min),
      max_(max),
      bucket_count_(bucket_count),
      num_samples_(num_samples) {}

bool MetricSample::IsValid() const {
  if (type() == INVALID || name().find(' ') != std::string::npos ||
      name().find('\0') != std::string::npos || name().empty()) {
    LOG(ERROR) << "Invalid sample type or name for histogram \"" << name()
               << "\"";
    return false;
  }
  if (type() == LINEAR_HISTOGRAM && max() == 1) {
    // No buckets: this is quietly ignored by Chrome, so better catch it here.
    LOG(ERROR) << "No buckets for linear histogram \"" << name() << "\"";
    return false;
  }
  if (type() == HISTOGRAM) {
    // Avoid integer overflow by forcing 64-bit ops.
    int64_t max64 = max();
    if (bucket_count() > max64 - min() + 2) {
      // Too many buckets: this is also quietly ignored by Chrome.
      // Note: a value x such that min <= x < max goes into a regular bucket.
      // Values outside that range go in the overflow and underflow buckets.
      LOG(ERROR) << "Too many buckets (" << bucket_count()
                 << ") for histogram \"" << name()
                 << "\", max for this range is " << max64 - min() + 2;
      return false;
    }
  }
  return true;
}

std::string MetricSample::ToString() const {
  if (type_ == CRASH) {
    return base::StringPrintf("crash%c%s%c", '\0', name().c_str(), '\0');
  } else if (type_ == SPARSE_HISTOGRAM) {
    return base::StringPrintf("sparsehistogram%c%s %d%c", '\0', name().c_str(),
                              sample_, '\0');
  } else if (type_ == LINEAR_HISTOGRAM) {
    return base::StringPrintf("linearhistogram%c%s %d %d%c", '\0',
                              name().c_str(), sample_, max_, '\0');
  } else if (type_ == HISTOGRAM) {
    if (num_samples_ > 1) {
      return base::StringPrintf("histogram%c%s %d %d %d %d %d%c", '\0',
                                name().c_str(), sample_, min_, max_,
                                bucket_count_, num_samples_, '\0');
    } else {
      return base::StringPrintf("histogram%c%s %d %d %d %d%c", '\0',
                                name().c_str(), sample_, min_, max_,
                                bucket_count_, '\0');
    }
  } else if (type_ == USER_ACTION) {
    CHECK_EQ(type_, USER_ACTION);
    return base::StringPrintf("useraction%c%s%c", '\0', name().c_str(), '\0');
  }

  NOTREACHED() << "Invalid sample type" << type_;
  return std::string();
}

int MetricSample::sample() const {
  CHECK_NE(type_, USER_ACTION);
  CHECK_NE(type_, CRASH);
  return sample_;
}

int MetricSample::min() const {
  CHECK_EQ(type_, HISTOGRAM);
  return min_;
}

int MetricSample::max() const {
  CHECK_NE(type_, CRASH);
  CHECK_NE(type_, USER_ACTION);
  CHECK_NE(type_, SPARSE_HISTOGRAM);
  return max_;
}

int MetricSample::bucket_count() const {
  CHECK_EQ(type_, HISTOGRAM);
  return bucket_count_;
}

int MetricSample::num_samples() const {
  CHECK_EQ(type_, HISTOGRAM);
  return num_samples_;
}

// static
MetricSample MetricSample::CrashSample(const std::string& crash_name) {
  return MetricSample(CRASH, crash_name, 0, 0, 0, 0);
}

// static
MetricSample MetricSample::HistogramSample(const std::string& histogram_name,
                                           int sample,
                                           int min,
                                           int max,
                                           int bucket_count,
                                           int num_samples) {
  return MetricSample(HISTOGRAM, histogram_name, sample, min, max, bucket_count,
                      num_samples);
}

// static
MetricSample MetricSample::ParseHistogram(
    const std::string& serialized_histogram) {
  std::vector<std::string> parts = base::SplitString(
      serialized_histogram, " ", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);

  if (parts.size() != 5 && parts.size() != 6)
    return MetricSample();
  int sample, min, max, bucket_count;
  if (parts[0].empty() || !base::StringToInt(parts[1], &sample) ||
      !base::StringToInt(parts[2], &min) ||
      !base::StringToInt(parts[3], &max) ||
      !base::StringToInt(parts[4], &bucket_count)) {
    return MetricSample();
  }

  int num_samples = 1;
  if (parts.size() == 6) {
    if (!base::StringToInt(parts[5], &num_samples)) {
      return MetricSample();
    }
  }

  return HistogramSample(parts[0], sample, min, max, bucket_count, num_samples);
}

// static
MetricSample MetricSample::SparseHistogramSample(
    const std::string& histogram_name, int sample) {
  return MetricSample(SPARSE_HISTOGRAM, histogram_name, sample, 0, 0, 0);
}

// static
MetricSample MetricSample::ParseSparseHistogram(
    const std::string& serialized_histogram) {
  std::vector<std::string> parts = base::SplitString(
      serialized_histogram, " ", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
  if (parts.size() != 2)
    return MetricSample();
  int sample;
  if (parts[0].empty() || !base::StringToInt(parts[1], &sample))
    return MetricSample();

  return SparseHistogramSample(parts[0], sample);
}

// static
MetricSample MetricSample::LinearHistogramSample(
    const std::string& histogram_name, int sample, int max) {
  return MetricSample(LINEAR_HISTOGRAM, histogram_name, sample, 0, max, 0);
}

// static
MetricSample MetricSample::ParseLinearHistogram(
    const std::string& serialized_histogram) {
  int sample, max;
  std::vector<std::string> parts = base::SplitString(
      serialized_histogram, " ", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
  if (parts.size() != 3)
    return MetricSample();
  if (parts[0].empty() || !base::StringToInt(parts[1], &sample) ||
      !base::StringToInt(parts[2], &max)) {
    return MetricSample();
  }

  return LinearHistogramSample(parts[0], sample, max);
}

// static
MetricSample MetricSample::UserActionSample(const std::string& action_name) {
  return MetricSample(USER_ACTION, action_name, 0, 0, 0, 0);
}

bool MetricSample::IsEqual(const MetricSample& metric) const {
  return type_ == metric.type_ && name_ == metric.name_ &&
         sample_ == metric.sample_ && min_ == metric.min_ &&
         max_ == metric.max_ && bucket_count_ == metric.bucket_count_ &&
         num_samples_ == metric.num_samples_;
}

}  // namespace metrics
