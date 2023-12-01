// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_VSH_VSH_CLIENT_H_
#define VM_TOOLS_VSH_VSH_CLIENT_H_

#include <sys/ioctl.h>  // For struct winsize.

#include <memory>
#include <string>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/scoped_file.h>
#include <brillo/asynchronous_signal_handler.h>
#include <brillo/message_loops/message_loop.h>
#include <google/protobuf/message_lite.h>
#include <vm_protos/proto_bindings/vsh.pb.h>

#include "vm_tools/vsh/scoped_termios.h"

namespace vm_tools {
namespace vsh {

// VshClient encapsulates a vsh client session.
class VshClient {
 public:
  static std::unique_ptr<VshClient> Create(base::ScopedFD sock_fd,
                                           base::ScopedFD stdout_fd,
                                           base::ScopedFD stderr_fd,
                                           const std::string& user,
                                           const std::string& container,
                                           const std::string& cwd,
                                           bool interactive);

  static std::unique_ptr<VshClient> CreateForTesting(base::ScopedFD sock_fd,
                                                     base::ScopedFD stdout_fd,
                                                     base::ScopedFD stderr_fd);
  ~VshClient() = default;

  int32_t container_shell_pid();
  int exit_code();

  // Helper function defined in vsh_client_fuzzer.cc.
  friend void vsh_client_fuzzer_run(const HostMessage& msg);

 private:
  explicit VshClient(base::ScopedFD sock_fd,
                     base::ScopedFD stdout_fd,
                     base::ScopedFD stderr_fd);
  VshClient(const VshClient&) = delete;
  VshClient& operator=(const VshClient&) = delete;

  bool Init(const std::string& user,
            const std::string& container,
            const std::string& cwd,
            bool interactive);

  bool HandleSignal(const struct signalfd_siginfo& siginfo);
  bool HandleWindowResizeSignal(const struct signalfd_siginfo& siginfo);
  void HandleVsockReadable();
  void HandleHostMessage(const HostMessage& msg);
  void HandleStdinReadable();
  bool SendCurrentWindowSize();
  bool GetCurrentWindowSize(struct winsize* ws);
  void CancelStdinTask();

  base::ScopedFD sock_fd_;
  int32_t container_shell_pid_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> sock_watcher_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> stdin_watcher_;

  // VshClient expects to take ownership of stdout and stderr file descriptors,
  // since it will close them once the guest has indicated EOF.
  //
  // These fds should be overridden for testing.
  base::ScopedFD stdout_fd_;
  base::ScopedFD stderr_fd_;

  brillo::AsynchronousSignalHandler signal_handler_;

  int exit_code_;
};

}  // namespace vsh
}  // namespace vm_tools

#endif  // VM_TOOLS_VSH_VSH_CLIENT_H_
