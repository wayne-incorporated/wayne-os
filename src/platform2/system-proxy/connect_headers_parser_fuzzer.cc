// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <curl/curl.h>

#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/run_loop.h>
#include <base/task/single_thread_task_executor.h>
#include <brillo/message_loops/base_message_loop.h>
#include <chromeos/patchpanel/socket.h>
#include <chromeos/patchpanel/socket_forwarder.h>

#include "system-proxy/proxy_connect_job.h"

namespace {
void ResolveProxyCallback(
    base::OnceClosure quit_task,
    const std::string&,
    base::OnceCallback<void(const std::list<std::string>&)>
        on_proxy_resolution_callback) {
  // Exit the fuzzer if the input fed to the test is a valid HTTP CONNECT
  // request.
  std::move(quit_task).Run();
}
void NullAuthenticationRequiredCallback(
    const std::string& proxy_url,
    const std::string& scheme,
    const std::string& realm,
    const std::string& bad_cached_credentials,
    base::RepeatingCallback<void(const std::string& credentials)>
        on_auth_acquired_callback) {}

void OnConnectionSetupFinished(base::OnceClosure quit_task,
                               std::unique_ptr<patchpanel::SocketForwarder>,
                               system_proxy::ProxyConnectJob*) {
  std::move(quit_task).Run();
}
}  // namespace

struct Environment {
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // Disable logging.
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  // Mock main task runner
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  brillo::BaseMessageLoop brillo_loop(task_executor.task_runner());
  brillo_loop.SetAsCurrent();

  base::RunLoop run_loop;

  int socket_pair[2];
  socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, socket_pair);
  base::ScopedFD reader_fd(socket_pair[0]);
  base::ScopedFD writer_fd(socket_pair[1]);
  int fds[2];

  socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
             0 /* protocol */, fds);
  patchpanel::Socket cros_client_socket((base::ScopedFD(fds[1])));

  auto connect_job = std::make_unique<system_proxy::ProxyConnectJob>(
      std::make_unique<patchpanel::Socket>(base::ScopedFD(fds[0])), "",
      CURLAUTH_ANY,
      base::BindOnce(&ResolveProxyCallback, run_loop.QuitClosure()),
      base::BindRepeating(&NullAuthenticationRequiredCallback),
      base::BindOnce(&OnConnectionSetupFinished, run_loop.QuitClosure()));
  connect_job->Start();
  cros_client_socket.SendTo(data, size);

  run_loop.Run();
  return 0;
}
