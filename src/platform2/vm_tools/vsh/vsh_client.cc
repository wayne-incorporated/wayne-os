// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/vsh/vsh_client.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/vm_sockets.h>  // Needs to come after sys/socket.h

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_split.h>
#include <brillo/asynchronous_signal_handler.h>
#include <brillo/flag_helper.h>
#include <brillo/message_loops/base_message_loop.h>
#include <brillo/syslog_logging.h>
#include <vm_protos/proto_bindings/vsh.pb.h>
#include <chromeos/constants/vm_tools.h>

#include "vm_tools/vsh/scoped_termios.h"
#include "vm_tools/vsh/utils.h"

using std::string;

namespace vm_tools {
namespace vsh {

// Pick a default exit status that will make it obvious if the remote end
// exited abnormally.
constexpr int kDefaultExitCode = 123;

std::unique_ptr<VshClient> VshClient::Create(base::ScopedFD sock_fd,
                                             base::ScopedFD stdout_fd,
                                             base::ScopedFD stderr_fd,
                                             const std::string& user,
                                             const std::string& container,
                                             const std::string& cwd,
                                             bool interactive) {
  auto client = std::unique_ptr<VshClient>(new VshClient(
      std::move(sock_fd), std::move(stdout_fd), std::move(stderr_fd)));

  if (!client->Init(user, container, cwd, interactive)) {
    return nullptr;
  }

  return client;
}

std::unique_ptr<VshClient> VshClient::CreateForTesting(
    base::ScopedFD sock_fd,
    base::ScopedFD stdout_fd,
    base::ScopedFD stderr_fd) {
  auto client = std::unique_ptr<VshClient>(new VshClient(
      std::move(sock_fd), std::move(stdout_fd), std::move(stderr_fd)));

  return client;
}

VshClient::VshClient(base::ScopedFD sock_fd,
                     base::ScopedFD stdout_fd,
                     base::ScopedFD stderr_fd)
    : sock_fd_(std::move(sock_fd)),
      container_shell_pid_(0),
      stdout_fd_(std::move(stdout_fd)),
      stderr_fd_(std::move(stderr_fd)),
      exit_code_(kDefaultExitCode) {}

bool VshClient::Init(const std::string& user,
                     const std::string& container,
                     const std::string& cwd,
                     bool interactive) {
  // Set up the connection with the guest. The setup process is:
  //
  // 1) Client opens connection and sends a SetupConnectionRequest.
  // 2) Server responds with a SetupConnectionResponse. If the response
  //    does not indicate READY status, the client must exit immediately.
  // 3) If the client receives READY, the server and client may exchange
  //    HostMessage and GuestMessage protobufs, with GuestMessages flowing
  //    from client(host) to server(guest), and vice versa for HostMessages.
  // 4) If the client or server receives a message with a new ConnectionStatus
  //    that does not indicate READY, the recepient must exit.
  SetupConnectionRequest connection_request;
  if (container.empty()) {
    connection_request.set_target(vm_tools::vsh::kVmShell);
  } else {
    connection_request.set_target(container);
  }

  connection_request.set_user(user);
  // cwd is either a path, or a pid where we will look up /proc/<pid>/cwd.
  if (!cwd.empty() && std::all_of(cwd.begin(), cwd.end(), isdigit)) {
    connection_request.set_cwd_pid(atoi(cwd.c_str()));
  } else {
    connection_request.set_cwd(cwd);
  }
  connection_request.set_nopty(!interactive);

  auto env = connection_request.mutable_env();

  // Default to forwarding the current TERM variable.
  const char* term_env = getenv("TERM");
  if (term_env)
    (*env)["TERM"] = std::string(term_env);

  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  std::vector<std::string> args = cl->GetArgs();

  // Forward any environment variables/args passed on the command line.
  bool env_done = false;
  for (const auto& arg : args) {
    if (!env_done) {
      std::vector<std::string> components = base::SplitString(
          arg, "=", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

      if (components.size() != 2) {
        env_done = true;
        connection_request.add_argv(arg);
      } else {
        (*env)[std::move(components[0])] = std::move(components[1]);
      }
    } else {
      connection_request.add_argv(arg);
    }
  }

  struct winsize ws;
  if (!GetCurrentWindowSize(&ws)) {
    LOG(ERROR) << "Failed to get initial window size";
    return false;
  }

  connection_request.set_window_rows(ws.ws_row);
  connection_request.set_window_cols(ws.ws_col);

  if (!SendMessage(sock_fd_.get(), connection_request)) {
    LOG(ERROR) << "Failed to send connection request";
    return false;
  }

  SetupConnectionResponse connection_response;
  if (!RecvMessage(sock_fd_.get(), &connection_response)) {
    LOG(ERROR) << "Failed to receive response from vshd";
    return false;
  }

  ConnectionStatus status = connection_response.status();
  if (status != READY) {
    LOG(ERROR) << "Server was unable to set up connection: "
               << connection_response.description();
    return false;
  }

  container_shell_pid_ = connection_response.pid();

  sock_watcher_ = base::FileDescriptorWatcher::WatchReadable(
      sock_fd_.get(), base::BindRepeating(&VshClient::HandleVsockReadable,
                                          base::Unretained(this)));
  // STDIN_FILENO may not be watchable if it's /dev/null, and WatchReadable will
  // CHECK in this case. So watch only if it's interactive tty.
  // Watch FIFO too to make `echo command | vsh` usable even it's not
  // interactive.
  bool is_stdin_watchable = interactive;
  if (!interactive) {
    struct stat buf;
    if (HANDLE_EINTR(fstat(STDIN_FILENO, &buf)) == 0) {
      is_stdin_watchable |= S_ISFIFO(buf.st_mode);
    } else {
      PLOG(ERROR) << "Failed to stat stdin fd";
    }
  }
  if (is_stdin_watchable) {
    stdin_watcher_ = base::FileDescriptorWatcher::WatchReadable(
        STDIN_FILENO, base::BindRepeating(&VshClient::HandleStdinReadable,
                                          base::Unretained(this)));
  }

  // Handle termination signals and SIGWINCH.
  signal_handler_.Init();
  for (int signal : {SIGINT, SIGTERM, SIGHUP, SIGQUIT}) {
    signal_handler_.RegisterHandler(
        signal,
        base::BindRepeating(&VshClient::HandleSignal, base::Unretained(this)));
  }
  signal_handler_.RegisterHandler(
      SIGWINCH, base::BindRepeating(&VshClient::HandleWindowResizeSignal,
                                    base::Unretained(this)));

  return true;
}

// Forwards a signal that's expected to terminate the process to the guest.
bool VshClient::HandleSignal(const struct signalfd_siginfo& siginfo) {
  GuestMessage guest_message;
  switch (siginfo.ssi_signo) {
    case SIGHUP:
      guest_message.set_signal(SIGNAL_HUP);
      break;
    case SIGINT:
      guest_message.set_signal(SIGNAL_INT);
      break;
    case SIGQUIT:
      guest_message.set_signal(SIGNAL_QUIT);
      break;
    case SIGTERM:
      guest_message.set_signal(SIGNAL_TERM);
      break;
    default:
      LOG(ERROR) << "Received unexpected signal number " << siginfo.ssi_signo;
      Shutdown();
      return false;
  }

  if (!SendMessage(sock_fd_.get(), guest_message)) {
    LOG(ERROR) << "Failed to send signal message";
    Shutdown();
    return false;
  }

  return false;
}

// Handles a window resize signal by sending the current window size to the
// remote.
bool VshClient::HandleWindowResizeSignal(
    const struct signalfd_siginfo& siginfo) {
  DCHECK_EQ(siginfo.ssi_signo, SIGWINCH);

  SendCurrentWindowSize();

  // This return value indicates whether or not the signal handler should be
  // unregistered! So, even if this succeeds, this should return false.
  return false;
}

// Receives a host message from the guest and takes action.
void VshClient::HandleVsockReadable() {
  HostMessage host_message;
  if (!RecvMessage(sock_fd_.get(), &host_message)) {
    PLOG(ERROR) << "Failed to receive message from server";
    Shutdown();
    return;
  }

  HandleHostMessage(host_message);
}

void VshClient::HandleHostMessage(const HostMessage& msg) {
  switch (msg.msg_case()) {
    case HostMessage::kDataMessage: {
      // Data messages from the guest should go to stdout/stderr.
      DataMessage data_message = msg.data_message();
      int target_fd = -1;
      switch (data_message.stream()) {
        case STDOUT_STREAM:
          target_fd = stdout_fd_.get();
          break;
        case STDERR_STREAM:
          target_fd = stderr_fd_.get();
          break;
        default:
          LOG(ERROR) << "Invalid stream type from guest: "
                     << data_message.stream();
          return;
      }

      if (data_message.data().size() == 0) {
        // On EOF from guest, close the host-side fd.
        if (data_message.stream() == STDOUT_STREAM) {
          stdout_fd_.reset();
        } else {
          stderr_fd_.reset();
        }
      }

      if (!base::WriteFileDescriptor(target_fd, data_message.data())) {
        PLOG(ERROR) << "Failed to write data to fd " << target_fd;
        return;
      }
      break;
    }
    case HostMessage::kStatusMessage: {
      // The remote side has an updated connection status, which likely means
      // it's time to Shutdown().
      ConnectionStatusMessage status_message = msg.status_message();
      ConnectionStatus status = status_message.status();

      if (status == EXITED) {
        exit_code_ = status_message.code();
        Shutdown();
      } else if (status != READY) {
        LOG(ERROR) << "vsh connection has exited abnormally: " << status;
        Shutdown();
        return;
      }
      break;
    }
    default:
      LOG(ERROR) << "Received unknown host message of type: " << msg.msg_case();
  }
}

// Forwards input from the host to the remote pseudoterminal.
void VshClient::HandleStdinReadable() {
  uint8_t buf[kMaxDataSize];
  GuestMessage guest_message;
  DataMessage* data_message = guest_message.mutable_data_message();

  ssize_t count = HANDLE_EINTR(read(STDIN_FILENO, buf, sizeof(buf)));

  if (count < 0) {
    PLOG(ERROR) << "Failed to read from stdin";
    Shutdown();
    return;
  } else if (count == 0) {
    CancelStdinTask();
  }

  data_message->set_stream(STDIN_STREAM);
  data_message->set_data(buf, count);

  if (!SendMessage(sock_fd_.get(), guest_message)) {
    LOG(ERROR) << "Failed to send guest data message";
    // Sending a partial message will break framing. Shut down the socket
    // write end, but don't quit entirely yet since there may be unprocessed
    // messages to read.
    CancelStdinTask();
    return;
  }
}

bool VshClient::SendCurrentWindowSize() {
  GuestMessage guest_message;
  WindowResizeMessage* resize_message = guest_message.mutable_resize_message();

  struct winsize ws;
  if (!GetCurrentWindowSize(&ws)) {
    return false;
  }

  resize_message->set_rows(ws.ws_row);
  resize_message->set_cols(ws.ws_col);

  if (!SendMessage(sock_fd_.get(), guest_message)) {
    LOG(ERROR) << "Failed to send tty window resize message";
    Shutdown();
    return false;
  }

  return true;
}

bool VshClient::GetCurrentWindowSize(struct winsize* ws) {
  DCHECK(ws);
  if (!isatty(STDIN_FILENO)) {
    ws->ws_row = 0;
    ws->ws_col = 0;
    return true;
  }

  if (ioctl(STDIN_FILENO, TIOCGWINSZ, ws) < 0) {
    PLOG(ERROR) << "Failed to get tty window size";
    return false;
  }

  return true;
}

void VshClient::CancelStdinTask() {
  stdin_watcher_.reset();
}

int32_t VshClient::container_shell_pid() {
  return container_shell_pid_;
}

int VshClient::exit_code() {
  return exit_code_;
}

}  // namespace vsh
}  // namespace vm_tools
