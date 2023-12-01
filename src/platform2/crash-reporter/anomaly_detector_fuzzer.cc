// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/anomaly_detector.h"

#include <cstddef>
#include <cstdint>
#include <memory>

#include <base/logging.h>
#include <brillo/process/process.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <gmock/gmock.h>
#include <metrics/metrics_library_mock.h>

#include "crash-reporter/crash_reporter_parser.h"
#include "crash-reporter/test_util.h"

namespace {
class Environment {
 public:
  Environment() {
    // Disable logging per instructions.
    logging::SetMinLogLevel(logging::LOGGING_FATAL);
  }
};

const size_t kArbitraryMaxSize = 16384;

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  FuzzedDataProvider stream(data, size);

  std::map<std::string, std::unique_ptr<anomaly::Parser>> parsers;
  parsers["audit"] =
      std::make_unique<anomaly::SELinuxParser>(stream.ConsumeBool());
  parsers["init"] =
      std::make_unique<anomaly::ServiceParser>(stream.ConsumeBool());
  parsers["kernel"] =
      std::make_unique<anomaly::KernelParser>(stream.ConsumeBool());
  parsers["powerd_suspend"] =
      std::make_unique<anomaly::SuspendParser>(stream.ConsumeBool());
  parsers["crash_reporter"] = std::make_unique<anomaly::CrashReporterParser>(
      std::make_unique<test_util::AdvancingClock>(),
      std::make_unique<testing::NiceMock<MetricsLibraryMock>>(),
      stream.ConsumeBool());

  const std::string journalTags[] = {"audit", "init", "kernel",
                                     "powerd_suspend", "crash_reporter"};

  while (stream.remaining_bytes() > 1) {
    const std::string tag = stream.PickValueInArray<std::string>(journalTags);
    size_t size = stream.remaining_bytes();
    if (size > kArbitraryMaxSize) {
      size = kArbitraryMaxSize;
    }
    const std::string message = stream.ConsumeRandomLengthString(size);
    parsers[tag]->ParseLogEntry(message);
    parsers[tag]->PeriodicUpdate();
  }
  return 0;
}
