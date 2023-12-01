// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/run_loop.h>
#include <base/task/single_thread_task_executor.h>
#include <base/test/test_mock_time_task_runner.h>
#include <brillo/message_loops/base_message_loop.h>
#include <libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h>

#include "bindings/worker_common.pb.h"
#include "system-proxy/protobuf_util.h"
#include "system-proxy/server_proxy.h"

namespace {
void NullClosure() {}
}  // namespace

struct Environment {
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // Disable logging.
  }
};

// ServerProxy implementation that receives input from a given file descriptor,
// instead of the default standard input file descriptor (STDIN_FILENO).
class FakeServerProxy : public system_proxy::ServerProxy {
 public:
  FakeServerProxy(base::ScopedFD stdin_fd, base::OnceClosure quit_task)
      : system_proxy::ServerProxy(base::BindOnce(&NullClosure)),
        stdin_fd_(std::move(stdin_fd)),
        quit_task_(std::move(quit_task)) {}
  FakeServerProxy(const FakeServerProxy&) = delete;
  FakeServerProxy& operator=(const FakeServerProxy&) = delete;
  ~FakeServerProxy() override = default;

  int GetStdinPipe() override { return stdin_fd_.get(); }

 private:
  void HandleStdinReadable() override {
    system_proxy::ServerProxy::HandleStdinReadable();
    std::move(quit_task_).Run();
  }

  base::ScopedFD stdin_fd_;
  base::OnceClosure quit_task_;
};

DEFINE_PROTO_FUZZER(const system_proxy::worker::WorkerConfigs& configs) {
  static Environment env;

  // Mock main task runner
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  brillo::BaseMessageLoop brillo_loop(task_executor.task_runner());
  brillo_loop.SetAsCurrent();
  base::RunLoop run_loop;

  int fds[2];
  CHECK(base::CreateLocalNonBlockingPipe(fds));
  base::ScopedFD stdin_read_fd(fds[0]);
  base::ScopedFD stdin_write_fd(fds[1]);

  auto server = std::make_unique<FakeServerProxy>(std::move(stdin_read_fd),
                                                  run_loop.QuitClosure());
  server->Init();
  // Send the config to the worker's stdin input.
  system_proxy::WriteProtobuf(stdin_write_fd.get(), configs);

  run_loop.Run();
}
