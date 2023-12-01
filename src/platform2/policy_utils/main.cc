// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sysexits.h>
#include <unistd.h>

#include <base/command_line.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_util.h>
#include <brillo/flag_helper.h>
#include <brillo/process/process.h>

#include "policy_utils/policy_tool.h"

namespace {

// Help message to show when the --help command line switch is specified.
constexpr char kHelpMessage[] =
    "\n"
    "Device Policy tool\n"
    "Set or clear device policies on the local device. Setting a local\n"
    "policy overrides the policy set in Chrome. The command format is:\n"
    "\n"
    "    policy [set|clear] PolicyName [value]\n"
    "\n"
    "The tool will try to automatically detect whether Google Chrome or\n"
    "Chromium is used. If that fails, you can use the options to force one\n"
    "or the other.\n"
    "\n"
    "Examples:\n"
    "    policy set ShowHomeButton true\n"
    "    policy clear ShowHomeButton\n\n"
    "Policy names are not case sensitive.";

constexpr char kUsageMessage[] =
    "\n"
    "Usage:\n"
    "    policy [set|clear] PolicyName [value]\n"
    "or\n"
    "    policy --help for more detailed help\n";

constexpr char kPolicyListHeader[] =
    "\n"
    "List of available policies:\n";

// Path to chrome executable in linux.
constexpr char kChromePath[] = "/opt/google/chrome/chrome";

// Return a PolicyTool singleton.
const policy_utils::PolicyTool& GetPolicyTool(bool for_chromium = false) {
  static policy_utils::PolicyTool policy_tool(
      for_chromium ? policy_utils::PolicyTool::kChromiumPolicyDirPath
                   : policy_utils::PolicyTool::kChromePolicyDirPath);
  return policy_tool;
}

// Show a list of all policies this tool can edit.
void ListPolicies() {
  const policy_utils::PolicyTool::PolicyList& policies =
      GetPolicyTool().get_policies();
  std::string name_list;
  for (auto& policy : policies) {
    name_list += "  " + policy + "\n";
  }

  LOG(INFO) << kPolicyListHeader << name_list;
}

// Run |process| and capture its stdout output to |output|.
int RunAndCaptureOutput(brillo::ProcessImpl* process, std::string* output) {
  constexpr size_t kBufferSize = 4096;

  process->RedirectUsingPipe(STDOUT_FILENO, false);
  if (process->Start()) {
    const int out = process->GetPipe(STDOUT_FILENO);
    char buffer[kBufferSize];
    output->clear();

    while (true) {
      const ssize_t count = HANDLE_EINTR(read(out, buffer, kBufferSize));
      if (count < 0) {
        process->Wait();
        break;
      }

      if (count == 0)
        return process->Wait();

      output->append(buffer, count);
    }
  }

  return -1;
}

// Query the chrome version string by running the chrome executable.
// Return whether successful.
bool GetChromeVersion(std::string* version) {
  brillo::ProcessImpl chrome;
  chrome.AddArg(kChromePath);
  chrome.AddArg("--version");

  int exit_code = RunAndCaptureOutput(&chrome, version);
  return (exit_code == EX_OK && !version->empty());
}

}  // namespace

int main(int argc, char** argv) {
  DEFINE_bool(list, false,
              "Show the list of policies this tool can set or clear");
  DEFINE_bool(chromium, false, "Force setting policies for Chromium");
  DEFINE_bool(chrome, false, "Force setting policies for Google Chrome");

  brillo::FlagHelper::Init(argc, argv, kHelpMessage);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();

  if (FLAGS_list) {
    ListPolicies();
    return 0;
  }

  const base::CommandLine::StringVector& args = cl->GetArgs();
  if (args.size() < 2) {
    LOG(INFO) << kUsageMessage;
    return 1;
  }

  // Determine whether we should set the policies for Google Chrome or Chromium,
  // either from cmd-line options or automatically.
  bool set_policies_for_chromium = false;
  if (FLAGS_chromium) {
    set_policies_for_chromium = true;
  } else if (FLAGS_chrome) {
    set_policies_for_chromium = false;
  } else {
    std::string chrome_version;
    if (!GetChromeVersion(&chrome_version)) {
      LOG(ERROR) << "Unable to get Chrome version.\n"
                    "You can use cmd-line options '--chrome' or '--chromium'\n"
                    "to force either Google Chrome or Chromium";
      return 1;
    }

    set_policies_for_chromium = base::StartsWith(
        chrome_version, "Chromium", base::CompareCase::INSENSITIVE_ASCII);
  }

  if (!GetPolicyTool(set_policies_for_chromium).DoCommand(args)) {
    LOG(INFO) << "Failed";
    return 1;
  }

  LOG(INFO) << "Done";
  return 0;
}
