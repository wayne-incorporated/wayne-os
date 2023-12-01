// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_BENCHMARK_H_
#define ML_BENCHMARK_H_

#include <cstdint>

#include <brillo/brillo_export.h>

// The following two functions are exported as test driver for running
// arbitrary tflite models within mlservice.
// Both function names and signatures should not be changed.

// Parses config_bytes as CrOSBenchmarkConfig and runs mlservice inference
// accordingly.
extern "C" BRILLO_EXPORT int32_t benchmark_start(const void* config_bytes,
                                                 int32_t config_bytes_size,
                                                 void** results_bytes,
                                                 int32_t* results_bytes_size);

// Deletes results_bytes.
extern "C" BRILLO_EXPORT void free_benchmark_results(void* results_bytes);

#endif  // ML_BENCHMARK_H_
