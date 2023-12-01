// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_BENCHMARK_JSON_SERIALIZER_H_
#define ML_BENCHMARK_JSON_SERIALIZER_H_

#include <optional>

#include <base/files/file_path.h>
#include <base/values.h>

#include "proto/benchmark_config.pb.h"

namespace ml_benchmark {

// In case of failure reports error to LOG(ERROR) and returns std::nullopt.
std::optional<base::Value::Dict> BenchmarkResultsToJson(
    const chrome::ml_benchmark::BenchmarkResults& results);

void WriteResultsToPath(const chrome::ml_benchmark::BenchmarkResults& results,
                        const base::FilePath& output_path);

}  // namespace ml_benchmark

#endif  // ML_BENCHMARK_JSON_SERIALIZER_H_
