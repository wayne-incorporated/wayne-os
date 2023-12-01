// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <fuzzer/FuzzedDataProvider.h>
#include <memory>

#include <base/logging.h>
#include <metrics/metrics_library.h>

#include "p2p/common/server_message.h"
#include "p2p/server/http_server_external_process.h"

using base::FilePath;
using p2p::server::HttpServerExternalProcess;
using p2p::util::kNumP2PServerMessageTypes;
using p2p::util::kP2PServerMagic;
using p2p::util::P2PServerMessage;

struct Environment {
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // Disable logging.
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  if (size < 8)
    return 0;

  FuzzedDataProvider data_provider(data, size);

  int64_t value;
  std::string value_bytes = data_provider.ConsumeBytesAsString(sizeof(value));
  memcpy(&value, value_bytes.data(), value_bytes.size());

  // The values of magic and message_type are constrained to ensure
  // OnMessageReceived does not exit().
  P2PServerMessage msg{
      .magic = kP2PServerMagic,
      .message_type = data_provider.ConsumeIntegralInRange<uint32_t>(
          0, kNumP2PServerMessageTypes - 1),
      .value = value,
  };

  // Create HTTP server external process.
  MetricsLibrary metrics_lib;
  auto process = std::make_unique<HttpServerExternalProcess>(
      &metrics_lib, FilePath("/tmp/p2p-fuzzing.XXXXXX"), FilePath("."), 0);

  // There's no need to Start() the process since OnMessageReceived only updates
  // member variables or sends metrics using the provided metrics library.
  HttpServerExternalProcess::OnMessageReceived(msg, process.get());

  return 0;
}
