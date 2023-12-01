// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POLICY_UTILS_POLICY_TOOL_H_
#define POLICY_UTILS_POLICY_TOOL_H_

#include <string>
#include <vector>

#include <base/command_line.h>

#include "policy_utils/policy_writer.h"

namespace policy_utils {

// Utility class to parse a command, policy name and optional parameters from a
// list of cmd-line arguments and perform the desired action.
class PolicyTool {
 public:
  // The directory path where JSON files should be stored to automatically
  // override policies in Chrome.
  constexpr static char kChromePolicyDirPath[] =
      "/etc/opt/chrome/policies/managed/";

  // The directory path where JSON files should be stored to automatically
  // override policies in Chromium.
  constexpr static char kChromiumPolicyDirPath[] =
      "/etc/chromium/policies/managed";

  // PolicyList is a list of policy names.
  typedef std::vector<const std::string> PolicyList;

  // Create a PolicyTool instance that writes policy JSON files to the specified
  // directory. Use one of the standard paths above for overriding policies in
  // Chrome or Chromium.
  explicit PolicyTool(const std::string& policy_dir_path);
  PolicyTool(const PolicyTool&) = delete;
  PolicyTool& operator=(const PolicyTool&) = delete;

  ~PolicyTool() = default;

  // Parse and perform the command specified by args. Return whether successful.
  bool DoCommand(const base::CommandLine::StringVector& args) const;

  // Return a list of policies this tool knows how to handle.
  static const PolicyList& get_policies();

 private:
  PolicyWriter writer_;
};

}  // namespace policy_utils

#endif  // POLICY_UTILS_POLICY_TOOL_H_
