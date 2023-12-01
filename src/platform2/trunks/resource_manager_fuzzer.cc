// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Fuzzer for Resource Manager.

#include <base/logging.h>

#include "trunks/fuzzed_command_transceiver.h"
#include "trunks/resource_manager.h"
#include "trunks/trunks_factory_for_test.h"

// Max fuzzed message length.
constexpr size_t kMaxMessageLength = 512;
// Max number of commands to send.
constexpr size_t kMaxCommands = 4;

struct Environment {
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // Disable logging.
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  FuzzedDataProvider data_provider(data, size);

  trunks::TrunksFactoryForTest test_factory;
  trunks::FuzzedCommandTransceiver transceiver(&data_provider,
                                               kMaxMessageLength);
  trunks::ResourceManager resource_manager(test_factory, &transceiver);

  size_t num_cmd =
      data_provider.ConsumeIntegralInRange<uint32_t>(1, kMaxCommands);
  for (size_t n = 0; n < num_cmd; n++) {
    resource_manager.SendCommandAndWait(transceiver.ConsumeCommand());
  }

  return 0;
}
