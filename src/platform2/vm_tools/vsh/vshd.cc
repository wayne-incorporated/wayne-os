// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <linux/vm_sockets.h>  // Needs to come after sys/socket.h

#include <algorithm>
#include <memory>
#include <string>

#include <base/at_exit.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/stl_util.h>
#include <base/strings/string_split.h>
#include <base/strings/stringprintf.h>
#include <brillo/asynchronous_signal_handler.h>
#include <brillo/flag_helper.h>
#include <brillo/message_loops/base_message_loop.h>
#include <brillo/syslog_logging.h>
#include <chromeos/constants/vm_tools.h>
#include <vm_protos/proto_bindings/vsh.pb.h>

#include "vm_tools/vsh/utils.h"
#include "vm_tools/vsh/vsh_forwarder.h"

using std::string;
using vm_tools::vsh::RecvMessage;
using vm_tools::vsh::SendMessage;
using vm_tools::vsh::Shutdown;
using vm_tools::vsh::VshForwarder;
using vm_tools::vsh::WriteKernelLogToFd;

namespace {

// Path to logging file.
constexpr char kDevKmsg[] = "/dev/kmsg";

// Prefix inserted before every log message.
std::string_view kLogPrefix = "vshd: ";

// File descriptor that points to /dev/kmsg. Needs to be a global variable
// because logging::LogMessageHandlerFunction is just a function pointer so we
// can't bind any variables to it via base::Bind*.
base::ScopedFD g_kmsg_fd;

bool LogToKmsg(logging::LogSeverity severity,
               const char* file,
               int line,
               size_t message_start,
               const string& message) {
  DCHECK(g_kmsg_fd.is_valid());

  // Even if the write wasn't successful, we can't log anything here because
  // this _is_ the logging function. Just return whether the write succeeded.
  return WriteKernelLogToFd(g_kmsg_fd.get(), severity, kLogPrefix, message,
                            message_start);
}

}  // namespace

int main(int argc, char** argv) {
  base::AtExitManager exit_manager;
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  // Save vshd logs to kernel's printk buffer so that we can see what happened
  // through pstore even when vsh doesn't work.
  int kmsg_fd = open(kDevKmsg, O_WRONLY | O_CLOEXEC);
  if (kmsg_fd != -1) {
    g_kmsg_fd.reset(kmsg_fd);
    logging::SetLogMessageHandler(LogToKmsg);
  } else {
    PLOG(WARNING) << "Failed to open /dev/kmsg";
  }

  LOG(INFO) << "vshd started";

  DEFINE_uint64(forward_to_host_port, 0, "Port to forward to on the host");
  DEFINE_bool(inherit_env, false, "Inherit the current environment variables");
  DEFINE_string(default_user, "chronos", "Default login user");
  DEFINE_bool(allow_to_switch_user, true,
              "Allow to switch to another user on login");

  brillo::FlagHelper::Init(argc, argv, "vsh daemon");
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  if (cl->GetArgs().size() > 0) {
    LOG(ERROR) << "Unknown extra command line arguments; exiting";
    return EXIT_FAILURE;
  }

  if (FLAGS_forward_to_host_port != 0) {
    uint32_t port = static_cast<uint32_t>(FLAGS_forward_to_host_port);
    if (port != FLAGS_forward_to_host_port) {
      LOG(ERROR) << "Port " << FLAGS_forward_to_host_port
                 << " is not a valid port";
      return EXIT_FAILURE;
    }

    base::ScopedFD sock_fd(socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (!sock_fd.is_valid()) {
      PLOG(ERROR) << "Failed to open vsock socket";
      return EXIT_FAILURE;
    }

    struct sockaddr_vm addr;
    memset(&addr, 0, sizeof(addr));
    addr.svm_family = AF_VSOCK;
    addr.svm_port = port;
    addr.svm_cid = 2;

    if (HANDLE_EINTR(connect(sock_fd.get(),
                             reinterpret_cast<struct sockaddr*>(&addr),
                             sizeof(addr))) < 0) {
      PLOG(ERROR) << "Failed to connect to vsh client";
      return EXIT_FAILURE;
    }

    // Set up and start the message loop.
    brillo::BaseMessageLoop message_loop;
    message_loop.SetAsCurrent();
    auto forwarder = VshForwarder::Create(std::move(sock_fd), FLAGS_inherit_env,
                                          std::move(FLAGS_default_user),
                                          FLAGS_allow_to_switch_user);

    if (!forwarder) {
      return EXIT_FAILURE;
    }

    message_loop.Run();
    return EXIT_SUCCESS;
  }

  // Create a socket to listen for incoming vsh connections.
  base::ScopedFD sock_fd(socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0));
  if (!sock_fd.is_valid()) {
    PLOG(ERROR) << "Failed to create socket";
    return EXIT_FAILURE;
  }

  struct sockaddr_vm addr;
  memset(&addr, 0, sizeof(addr));
  addr.svm_family = AF_VSOCK;
  addr.svm_port = vm_tools::kVshPort;
  addr.svm_cid = VMADDR_CID_ANY;

  if (bind(sock_fd.get(), reinterpret_cast<const struct sockaddr*>(&addr),
           sizeof(addr)) < 0) {
    PLOG(ERROR) << "Failed to bind vshd port";
    return EXIT_FAILURE;
  }

  // Allow a backlog of up to 32 connections. This is exceedingly generous since
  // this daemon forks after accepting a connection.
  if (listen(sock_fd.get(), 32) < 0) {
    PLOG(ERROR) << "Failed to listen";
    return EXIT_FAILURE;
  }

  // Block SIGCHLD and set up a signalfd so the main daemon can reap its
  // children.
  sigset_t sigchld_mask, saved_mask;
  int result = sigemptyset(&sigchld_mask);
  DCHECK_EQ(result, 0);
  result = sigaddset(&sigchld_mask, SIGCHLD);
  DCHECK_EQ(result, 0);
  if (sigprocmask(SIG_BLOCK, &sigchld_mask, &saved_mask) < 0) {
    PLOG(ERROR) << "Failed to block SIGCHLD";
    return EXIT_FAILURE;
  }

  base::ScopedFD signal_fd(
      signalfd(-1, &sigchld_mask, SFD_NONBLOCK | SFD_CLOEXEC));
  if (!signal_fd.is_valid()) {
    PLOG(ERROR) << "Failed to set up signalfd";
    return EXIT_FAILURE;
  }

  struct pollfd pollfds[] = {
      {signal_fd.get(), POLLIN, 0},
      {sock_fd.get(), POLLIN, 0},
  };
  const int num_pollfds = std::size(pollfds);

  while (true) {
    if (poll(pollfds, num_pollfds, -1) < 0) {
      PLOG(ERROR) << "Failed to poll";
      return EXIT_FAILURE;
    }

    for (int i = 0; i < num_pollfds; i++) {
      if (!(pollfds[i].revents & POLLIN))
        continue;

      if (i == 0) {
        // signalfd.
        struct signalfd_siginfo siginfo;
        if (read(signal_fd.get(), &siginfo, sizeof(siginfo)) !=
            sizeof(siginfo)) {
          PLOG(ERROR) << "Failed to read entire signalfd siginfo";
          continue;
        }
        DCHECK_EQ(siginfo.ssi_signo, SIGCHLD);

        // Reap any child exit statuses.
        int waitpid_exit;
        while ((waitpid_exit = waitpid(-1, nullptr, WNOHANG)) > 0)
          continue;
        if (waitpid_exit < 0 && errno != ECHILD)
          PLOG(ERROR) << "Failed to clean up child process";
      } else if (i == 1) {
        // sock_fd.
        struct sockaddr_vm peer_addr;
        socklen_t addr_size = sizeof(peer_addr);
        base::ScopedFD peer_sock_fd(HANDLE_EINTR(accept4(
            sock_fd.get(), reinterpret_cast<struct sockaddr*>(&peer_addr),
            &addr_size, SOCK_CLOEXEC)));
        if (!peer_sock_fd.is_valid()) {
          PLOG(ERROR) << "Failed to accept connection from client";
          continue;
        }

        int pid = fork();

        if (pid == 0) {
          // The child needs to restore the original signal mask, and close
          // the listening sock_fd and signalfd manually. These fds will be
          // closed automatically on exec() anyway, but it's better not to allow
          // the unprivileged forwarder to have access to either of these.
          if (sigprocmask(SIG_SETMASK, &saved_mask, nullptr) < 0) {
            PLOG(ERROR) << "Failed to restore signal mask after fork";
          }
          sock_fd.reset();
          signal_fd.reset();
          // Set up and start the message loop.
          brillo::BaseMessageLoop message_loop;
          message_loop.SetAsCurrent();
          auto forwarder = VshForwarder::Create(
              std::move(peer_sock_fd), FLAGS_inherit_env,
              std::move(FLAGS_default_user), FLAGS_allow_to_switch_user);

          if (!forwarder) {
            return EXIT_FAILURE;
          }

          message_loop.Run();
          return EXIT_SUCCESS;
        } else if (pid < 0) {
          PLOG(ERROR) << "Failed to fork child";
        }
      }
    }
  }

  return EXIT_SUCCESS;
}
