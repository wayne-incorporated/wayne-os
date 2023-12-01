// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>

#include "metrics/serialization/metric_sample.h"
#include "metrics/serialization/serialization_utils.h"

// Reduced batch size for fuzzing to fit within the default input size limit
// used by libfuzzer (currently 1MB).
constexpr size_t kSampleBatchMaxLengthForFuzzing =
    10 * metrics::SerializationUtils::kMessageMaxLength;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  logging::SetMinLogLevel(logging::LOGGING_FATAL);  // Disable logging.

  base::ScopedTempDir temp_dir;
  CHECK(temp_dir.CreateUniqueTempDir());
  base::FilePath metrics_file = temp_dir.GetPath().Append("metrics");

  CHECK_EQ(size, base::WriteFile(metrics_file,
                                 reinterpret_cast<const char*>(data), size));

  std::vector<metrics::MetricSample> samples;
  metrics::SerializationUtils::ReadAndTruncateMetricsFromFile(
      metrics_file.value(), &samples, kSampleBatchMaxLengthForFuzzing);

  return 0;
}
