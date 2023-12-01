/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "features/hdrnet/tests/hdrnet_processor_test_fixture.h"

#include <benchmark/benchmark.h>
#include <sync/sync.h>

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/test/test_timeouts.h>

namespace cros {

void RunHdrnetProcessor(benchmark::State& state,
                        HdrNetProcessorTestFixture& fixture) {
  HdrnetMetrics metrics;
  for (auto _ : state) {
    auto result = fixture.ProduceFakeCaptureResult();
    fixture.ProcessResultMetadata(&result);
    base::ScopedFD fence = fixture.Run(result.frame_number(), metrics);
    constexpr int kFenceWaitTimeoutMs = 300;
    CHECK_EQ(sync_wait(fence.get(), kFenceWaitTimeoutMs), 0);
  }
}

static void BM_HdrNetProcessorFullProcessing(benchmark::State& state) {
  Size input_size = {static_cast<uint32_t>(state.range(0)),
                     static_cast<uint32_t>(state.range(1))};
  std::vector<Size> output_sizes = {input_size};
  HdrNetProcessorTestFixture fixture(input_size, HAL_PIXEL_FORMAT_YCBCR_420_888,
                                     output_sizes,
                                     /*use_default_adapter=*/false);
  RunHdrnetProcessor(state, fixture);
}
BENCHMARK(BM_HdrNetProcessorFullProcessing)
    ->Unit(benchmark::kMillisecond)
    ->Args({640, 360})     // 0.23Mpix (360p)
    ->Args({1280, 720})    // 0.9Mpix (720p)
    ->Args({1920, 1080})   // 2Mpix (1080p)
    ->Args({2560, 1920})   // 5Mpix
    ->Args({3264, 2448})   // 8Mpix
    ->Args({3840, 2880});  // 13Mpix

static void BM_HdrNetProcessorCoreProcessing(benchmark::State& state) {
  Size input_size = {static_cast<uint32_t>(state.range(0)),
                     static_cast<uint32_t>(state.range(1))};
  std::vector<Size> output_sizes = {input_size};
  HdrNetProcessorTestFixture fixture(input_size, HAL_PIXEL_FORMAT_YCBCR_420_888,
                                     output_sizes,
                                     /*use_default_adapter=*/true);
  RunHdrnetProcessor(state, fixture);
}
BENCHMARK(BM_HdrNetProcessorCoreProcessing)
    ->Unit(benchmark::kMillisecond)
    ->Args({640, 360})     // 0.23Mpix (360p)
    ->Args({1280, 720})    // 0.9Mpix (720p)
    ->Args({1920, 1080})   // 2Mpix (1080p)
    ->Args({2560, 1920})   // 5Mpix
    ->Args({3264, 2448})   // 8Mpix
    ->Args({3840, 2880});  // 13Mpix

}  // namespace cros

// Use our own main function instead of BENCHMARK_MAIN() because we need to
// initialize libchrome test supports.
int main(int argc, char** argv) {
  base::AtExitManager exit_manager;
  base::CommandLine::Init(argc, argv);
  TestTimeouts::Initialize();
  ::benchmark::Initialize(&argc, argv);
  if (::benchmark::ReportUnrecognizedArguments(argc, argv)) {
    return 1;
  }
  ::benchmark::RunSpecifiedBenchmarks();
  ::benchmark::Shutdown();
  return 0;
}
