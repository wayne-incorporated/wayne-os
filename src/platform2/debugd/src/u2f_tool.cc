// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/u2f_tool.h"

#include <set>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_split.h>
#include <brillo/file_utils.h>
#include <brillo/files/file_util.h>
#include <chromeos/dbus/debugd/dbus-constants.h>

#include "debugd/src/process_with_output.h"

namespace debugd {

namespace {

constexpr char kOverrideConfigDir[] = "/var/lib/u2f/force";
constexpr char kJobName[] = "u2fd";

constexpr const char* kKnownFlags[] = {
    u2f_flags::kU2f,      u2f_flags::kG2f,           u2f_flags::kVerbose,
    u2f_flags::kUserKeys, u2f_flags::kAllowlistData, u2f_flags::kCorpProtocol,
};

int ControlU2fd(bool start) {
  const char* action = start ? "start" : "stop";

  return ProcessWithOutput::RunProcess("/sbin/initctl", {action, kJobName},
                                       true,     // requires root
                                       false,    // disable_sandbox
                                       nullptr,  // stdin
                                       nullptr,  // stdout
                                       nullptr,  // stderr
                                       nullptr);
}

base::FilePath FlagFile(const std::string& flag) {
  return base::FilePath(kOverrideConfigDir).Append(flag + ".force");
}

}  // namespace

std::string U2fTool::SetFlags(const std::string& flags) {
  std::string result;

  // Stop the u2fd daemon.
  ControlU2fd(false);

  LOG(INFO) << "Set u2fd flags:" << flags;
  std::set<std::string> all_flags;
  for (const char* cur : kKnownFlags) {
    all_flags.insert(cur);

    // Clean-up existing flag.
    brillo::DeleteFile(FlagFile(cur));
  }

  // Iterate over the new flags.
  for (const std::string& cur : base::SplitString(
           flags, ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY)) {
    // Validate the flag name.
    if (all_flags.find(cur) != all_flags.end())
      brillo::TouchFile(FlagFile(cur.c_str()));
    else
      result += "Discarded unknown flag '" + cur + "'.\n";
  }

  // Start the u2fd daemon with the new configuration.
  if (ControlU2fd(true))
    result += "Failed to restart u2fd.";

  // Returns the outcome of the operations (empty for success).
  return result;
}

std::string U2fTool::GetFlags() const {
  std::vector<std::string> flags;
  for (const char* cur : kKnownFlags) {
    if (base::PathExists(FlagFile(cur))) {
      flags.push_back(cur);
    }
  }

  return base::JoinString(flags, ",");
}

}  // namespace debugd
