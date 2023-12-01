// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include <base/logging.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <gmock/gmock.h>
#include <libhwsec/factory/fuzzed_factory.h>
#include <metrics/metrics_library_mock.h>

#include "u2fd/allowlisting_util.h"
#include "u2fd/fuzzers/fuzzed_allowlisting_util_factory.h"
#include "u2fd/fuzzers/fuzzed_user_state.h"
#include "u2fd/u2f_msg_handler.h"

namespace {

// Provide max iterations for a single fuzz run, otherwise it might timeout.
constexpr int kMaxIterations = 100;

}  // namespace

class Environment {
 public:
  Environment() { logging::SetMinLogLevel(logging::LOG_FATAL); }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  FuzzedDataProvider data_provider(data, size);

  u2f::FuzzedAllowlistingUtilFactory allowlisting_util_factory(&data_provider);
  auto allowlisting_util = allowlisting_util_factory.CreateAllowlistingUtil();
  std::function<void()> request_presence = []() {
    // do nothing
  };
  auto user_state = std::make_unique<u2f::FuzzedUserState>(&data_provider);
  auto hwsec_factory = std::make_unique<hwsec::FuzzedFactory>(data_provider);
  auto u2f_frontend = hwsec_factory->GetU2fVendorFrontend();
  testing::NiceMock<MetricsLibraryMock> mock_metrics;
  bool allow_g2f_attestation = data_provider.ConsumeBool();

  auto u2f_msg_handler = std::make_unique<u2f::U2fMessageHandler>(
      std::move(allowlisting_util), request_presence, user_state.get(),
      u2f_frontend.get(), nullptr, &mock_metrics, allow_g2f_attestation,
      /*u2f_corp_processor=*/nullptr);

  int rounds = 0;
  while (data_provider.remaining_bytes() > 0 && rounds < kMaxIterations) {
    u2f_msg_handler->ProcessMsg(data_provider.ConsumeRandomLengthString());
    user_state->NextState();
    rounds++;
  }

  return 0;
}
