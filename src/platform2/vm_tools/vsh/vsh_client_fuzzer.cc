// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/vsh/vsh_client.h"

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <brillo/message_loops/base_message_loop.h>
#include <libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h>
#include <vm_protos/proto_bindings/vsh.pb.h>

using vm_tools::vsh::HostMessage;
using vm_tools::vsh::VshClient;

namespace {

base::ScopedFD dup_fd_or_die(int fd) {
  base::ScopedFD dup_fd(dup(fd));
  if (!dup_fd.is_valid()) {
    PLOG(FATAL) << "Failed to dup fd";
  }

  return dup_fd;
}

class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // <- DISABLE LOGGING.
  }
};

}  // namespace

namespace vm_tools {
namespace vsh {

void vsh_client_fuzzer_run(const HostMessage& msg) {
  base::ScopedFD devnull_fd(
      HANDLE_EINTR(open("/dev/null", O_CLOEXEC | O_RDWR)));
  base::ScopedFD stdout_fd = dup_fd_or_die(devnull_fd.get());
  base::ScopedFD stderr_fd = dup_fd_or_die(devnull_fd.get());

  brillo::BaseMessageLoop message_loop;
  message_loop.SetAsCurrent();
  std::unique_ptr<VshClient> client(VshClient::CreateForTesting(
      std::move(devnull_fd), std::move(stdout_fd), std::move(stderr_fd)));
  client->HandleHostMessage(msg);
}

}  // namespace vsh
}  // namespace vm_tools

DEFINE_PROTO_FUZZER(const vm_tools::vsh::HostMessage& input) {
  static Environment env;

  vsh_client_fuzzer_run(input);
}
