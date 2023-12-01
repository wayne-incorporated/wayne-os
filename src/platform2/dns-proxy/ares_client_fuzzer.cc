// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/at_exit.h>
#include <base/logging.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "dns-proxy/ares_client.h"

#include <base/task/single_thread_task_executor.h>
#include <brillo/message_loops/base_message_loop.h>

namespace dns_proxy {
namespace {

class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // <- DISABLE LOGGING.
  }
  base::AtExitManager at_exit;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  brillo::BaseMessageLoop loop(task_executor.task_runner());
  loop.SetAsCurrent();

  FuzzedDataProvider provider(data, size);
  AresClient ares_client(base::Seconds(1));

  while (provider.remaining_bytes() > 0) {
    auto msg = provider.ConsumeBytes<unsigned char>(
        std::numeric_limits<unsigned int>::max());
    ares_client.Resolve(msg.data(), msg.size(),
                        base::BindRepeating([](int, uint8_t*, size_t) {}),
                        "8.8.8.8");
    base::RunLoop().RunUntilIdle();
  }

  return 0;
}

}  // namespace
}  // namespace dns_proxy
