// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "printscanmgr/daemon/lp_tools.h"

#include <signal.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <brillo/process/process.h>

#include "printscanmgr/cups_uri_helper/cups_uri_helper_utils.h"

namespace printscanmgr {

namespace {

constexpr char kLpadminCommand[] = "/usr/sbin/lpadmin";
constexpr char kLpstatCommand[] = "/usr/bin/lpstat";
constexpr char kTestPPDCommand[] = "/usr/bin/cupstestppd";

}  // namespace

int LpToolsImpl::RunCommand(const std::string& command,
                            const std::vector<std::string>& arg_list,
                            const std::vector<uint8_t>* std_input,
                            std::string* out) const {
  brillo::ProcessImpl process;
  process.RedirectOutputToMemory(/*combine=*/false);

  process.AddArg(command);
  for (const std::string& arg : arg_list) {
    process.AddArg(arg);
  }

  // Starts a process, writes data from the buffer to its standard input and
  // waits for the process to finish.
  int result = kRunError;
  process.RedirectUsingPipe(STDIN_FILENO, true);
  if (process.Start()) {
    // Ignore SIGPIPE.
    const struct sigaction kSigIgn = {.sa_handler = SIG_IGN,
                                      .sa_flags = SA_RESTART};
    struct sigaction old_sa;
    if (sigaction(SIGPIPE, &kSigIgn, &old_sa)) {
      PLOG(ERROR) << "sigaction failed";
      return 1;
    }
    // Restore the old signal handler at the end of the scope.
    const base::ScopedClosureRunner kRestoreSignal(base::BindOnce(
        [](const struct sigaction& sa) {
          if (sigaction(SIGPIPE, &sa, nullptr)) {
            PLOG(ERROR) << "sigaction failed";
          }
        },
        old_sa));
    int stdin_fd = process.GetPipe(STDIN_FILENO);

    bool succeeded = true;
    if (std_input) {
      succeeded &= base::WriteFileDescriptor(stdin_fd, *std_input);
    }
    succeeded &= IGNORE_EINTR(close(stdin_fd)) == 0;
    // Kill the process if writing to or closing the pipe fails.
    if (!succeeded) {
      process.Kill(SIGKILL, 0);
    }
    result = process.Wait();
    if (out) {
      *out = process.GetOutputString(STDOUT_FILENO);
    }
  }

  if (result != 0) {
    std::string error_msg = process.GetOutputString(STDERR_FILENO);
    LOG(ERROR) << "Child process exited with status " << result;
    LOG(ERROR) << "stderr was: " << error_msg;
  }

  return result;
}

// Runs lpadmin with the provided |arg_list| and |std_input|.
int LpToolsImpl::Lpadmin(const std::vector<std::string>& arg_list,
                         const std::vector<uint8_t>* std_input) {
  // Run in lp group so we can read and write /run/cups/cups.sock.
  return RunCommand(kLpadminCommand, arg_list, std_input);
}

// Runs lpstat with the provided |arg_list| and |std_input|.
int LpToolsImpl::Lpstat(const std::vector<std::string>& arg_list,
                        std::string* output) {
  // Run in lp group so we can read and write /run/cups/cups.sock.
  return RunCommand(kLpstatCommand, arg_list, /*std_input=*/nullptr, output);
}

int LpToolsImpl::CupsTestPpd(const std::vector<uint8_t>& ppd_content) const {
  return RunCommand(kTestPPDCommand,
                    {"-W", "translations", "-W", "constraints", "-"},
                    &ppd_content);
}

bool LpToolsImpl::CupsUriHelper(const std::string& uri) const {
  return cups_helper::UriSeemsReasonable(uri);
}

const base::FilePath& LpToolsImpl::GetCupsPpdDir() const {
  static const base::FilePath kCupsPpdDir("/var/cache/cups/printers/ppd");
  return kCupsPpdDir;
}

}  // namespace printscanmgr
