// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "syslog-cat/syslogcat.h"

#include <sys/socket.h>
#include <sys/un.h>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/stringprintf.h>

namespace {

base::ScopedFD PrepareSocket(const std::string& identifier,
                             int severity,
                             int pid,
                             const base::FilePath& socket_path) {
  DCHECK(!identifier.empty());
  DCHECK_GE(severity, 0);
  DCHECK_LE(severity, 7);

  // Open the unix socket to write logs.
  base::ScopedFD sock(
      socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_CLOEXEC, 0));
  if (!sock.is_valid()) {
    PLOG(ERROR) << "opening stream socket";
    return base::ScopedFD();
  }

  // Connect the syslog unix socket file.
  struct sockaddr_un server = {};
  server.sun_family = AF_UNIX;
  CHECK_GT(sizeof(server.sun_path), socket_path.value().length());
  strncpy(server.sun_path, socket_path.value().c_str(),
          sizeof(server.sun_path));
  if (HANDLE_EINTR(connect(sock.get(), (struct sockaddr*)&server,
                           sizeof(struct sockaddr_un))) < 0) {
    PLOG(ERROR) << "connecting stream socket";
    return base::ScopedFD();
  }

  // Construct the header string to send.
  std::string header = base::StringPrintf("TAG=%s[%d]\nPRIORITY=%d\n\n",
                                          identifier.c_str(), pid, severity);

  // Send headers (tag and severity).
  if (!base::WriteFileDescriptor(sock.get(), header)) {
    PLOG(ERROR) << "writing headers on stream socket";
    return base::ScopedFD();
  }

  return sock;
}

bool CreateSocketAndBindToFD(const std::string& identifier,
                             int severity,
                             int pid,
                             int target_fd,
                             const base::FilePath& socket_path) {
  base::ScopedFD sock = PrepareSocket(identifier, severity, pid, socket_path);
  if (!sock.is_valid()) {
    LOG(ERROR) << "Failed to open the rsyslog socket for stderr.";
    return false;
  }

  // Connect the socket to stderr.
  if (HANDLE_EINTR(dup2(sock.get(), target_fd)) == -1) {
    PLOG(ERROR) << "duping the stderr";
    return false;
  }

  return true;
}

}  // namespace

void ExecuteCommandWithRedirection(
    const std::string& target_command,
    const std::vector<const char*>& target_command_argv,
    const std::string& identifier,
    int severity_stdout,
    int severity_stderr,
    const base::FilePath& socket_path_stdout,
    const base::FilePath& socket_path_stderr) {
  // Prepare a pid.
  pid_t pid = getpid();

  // Open the unix socket to redirect logs from stdout (and stderr).
  bool ret_stdout = CreateSocketAndBindToFD(identifier, severity_stdout, pid,
                                            STDOUT_FILENO, socket_path_stdout);
  CHECK(ret_stdout) << "Failed to bind stdout.";

  // Open the unix socket to redirect logs from stderr.
  // We prepare a separate socket for stderr even if the severities are same,
  // in order to prevent interleave of simultaneous lines.
  bool ret_stderr = CreateSocketAndBindToFD(identifier, severity_stderr, pid,
                                            STDERR_FILENO, socket_path_stderr);
  CHECK(ret_stderr) << "Failed to bind stderr.";

  // Execute the target process.
  execvp(const_cast<char*>(target_command.c_str()),
         const_cast<char**>(target_command_argv.data()));

  /////////////////////////////////////////////////////////////////////////////
  // The code below is executed only when the execvp() above failed.
  // (eg. the executable doesn't exist, or is not executable)

  PLOG(ERROR) << "execvp '" << target_command << "'";
}
