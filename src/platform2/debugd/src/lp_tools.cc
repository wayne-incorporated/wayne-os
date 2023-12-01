// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/lp_tools.h"

#include <signal.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>

#include "debugd/src/helper_utils.h"

namespace debugd {

namespace {

constexpr char kLpadminCommand[] = "/usr/sbin/lpadmin";
constexpr char kLpadminSeccompPolicy[] =
    "/usr/share/policy/lpadmin-seccomp.policy";
constexpr char kLpstatCommand[] = "/usr/bin/lpstat";
constexpr char kLpstatSeccompPolicy[] =
    "/usr/share/policy/lpstat-seccomp.policy";
constexpr char kTestPPDCommand[] = "/usr/bin/cupstestppd";
constexpr char kTestPPDSeccompPolicy[] =
    "/usr/share/policy/cupstestppd-seccomp.policy";
constexpr char kUriHelperBasename[] = "cups_uri_helper";
constexpr char kUriHelperSeccompPolicy[] =
    "/usr/share/policy/cups-uri-helper.policy";

constexpr char kLpadminUser[] = "lpadmin";
constexpr char kLpadminGroup[] = "lpadmin";
constexpr char kLpGroup[] = "lp";

}  // namespace

// Returns the exit code for the executed process.
int LpToolsImpl::RunAsUser(const std::string& user,
                           const std::string& group,
                           const std::string& command,
                           const std::string& seccomp_policy,
                           const ProcessWithOutput::ArgList& arg_list,
                           const std::vector<uint8_t>* std_input,
                           bool inherit_usergroups,
                           const base::EnvironmentMap& env,
                           std::string* out) const {
  ProcessWithOutput process;
  process.set_separate_stderr(true);
  process.SandboxAs(user, group);

  if (!seccomp_policy.empty())
    process.SetSeccompFilterPolicyFile(seccomp_policy);

  if (inherit_usergroups)
    process.InheritUsergroups();

  if (!env.empty())
    process.SetEnvironmentVariables(env);

  if (!process.Init())
    return ProcessWithOutput::kRunError;

  process.AddArg(command);
  for (const std::string& arg : arg_list) {
    process.AddArg(arg);
  }

  // Starts a process, writes data from the buffer to its standard input and
  // waits for the process to finish.
  int result = ProcessWithOutput::kRunError;
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
    if (out && !process.GetOutput(out)) {
      PLOG(ERROR) << "Failed to get process output";
      return 1;
    }
  }

  if (result != 0) {
    std::string error_msg;
    process.GetError(&error_msg);
    LOG(ERROR) << "Child process exited with status " << result;
    LOG(ERROR) << "stderr was: " << error_msg;
  }

  return result;
}

// Runs lpadmin with the provided |arg_list| and |std_input|.
int LpToolsImpl::Lpadmin(const ProcessWithOutput::ArgList& arg_list,
                         bool inherit_usergroups,
                         const base::EnvironmentMap& env,
                         const std::vector<uint8_t>* std_input) {
  // Run in lp group so we can read and write /run/cups/cups.sock.
  return RunAsUser(kLpadminUser, kLpGroup, kLpadminCommand,
                   kLpadminSeccompPolicy, arg_list, std_input,
                   inherit_usergroups, env);
}

// Runs lpstat with the provided |arg_list| and |std_input|.
int LpToolsImpl::Lpstat(const ProcessWithOutput::ArgList& arg_list,
                        std::string* output) {
  // Run in lp group so we can read and write /run/cups/cups.sock.
  return RunAsUser(kLpadminUser, kLpGroup, kLpstatCommand, kLpstatSeccompPolicy,
                   arg_list,
                   /*std_input=*/nullptr,
                   /*inherit_usergroups=*/false,
                   /*env=*/{}, output);
}

int LpToolsImpl::CupsTestPpd(const std::vector<uint8_t>& ppd_content) const {
  return RunAsUser(
      kLpadminUser, kLpadminGroup, kTestPPDCommand, kTestPPDSeccompPolicy,
      {"-W", "translations", "-W", "constraints", "-"}, &ppd_content);
}

int LpToolsImpl::CupsUriHelper(const std::string& uri) const {
  std::string helper_path;
  if (!GetHelperPath(kUriHelperBasename, &helper_path)) {
    DCHECK(false) << "GetHelperPath() failed to return the CUPS URI helper!";
    return 127;  // Shell exit code for command not found.
  }

  ProcessWithOutput::ArgList args = {uri};
  return RunAsUser(SandboxedProcess::kDefaultUser,
                   SandboxedProcess::kDefaultGroup, helper_path,
                   kUriHelperSeccompPolicy, args);
}

const base::FilePath& LpToolsImpl::GetCupsPpdDir() const {
  static const base::FilePath kCupsPpdDir("/var/cache/cups/printers/ppd");
  return kCupsPpdDir;
}

int LpToolsImpl::Chown(const std::string& path,
                       uid_t owner,
                       gid_t group) const {
  return chown(path.c_str(), owner, group);
}

}  // namespace debugd
