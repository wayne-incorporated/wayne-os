// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "policy_utils/policy_tool.h"

#include <optional>

#include <base/check_op.h>
#include <base/logging.h>
#include <base/strings/string_util.h>

namespace {
using base::CommandLine;
using base::CompareCaseInsensitiveASCII;
using policy_utils::PolicyWriter;

// The command that is being executed.
enum class Command { CMD_CLEAR, CMD_SET, CMD_UNKNOWN };

// Individual policies that this tool can handle.
constexpr char kPolicyDeviceAllowBluetooth[] = "DeviceAllowBlueTooth";
constexpr char kShowHomeButton[] = "ShowHomeButton";
constexpr char kBookmarkBarEnabled[] = "BookmarkBarEnabled";

// The same policies, bundled up in a list.
const policy_utils::PolicyTool::PolicyList known_policies = {
    kBookmarkBarEnabled, kPolicyDeviceAllowBluetooth, kShowHomeButton};

// Compare two strings for equality ignoring case.
bool IsEqualNoCase(const std::string& a, const std::string& b) {
  return CompareCaseInsensitiveASCII(a, b) == 0;
}

// Returns whether the policy, identified by its name, is supported.
bool VerifyPolicyName(const std::string& policy_name) {
  for (const std::string& policy : known_policies) {
    if (IsEqualNoCase(policy, policy_name))
      return true;
  }
  return false;
}

// Parse and return the command from the cmd-line arguments. Returns
// Command::CMD_UNKNOWN if the command string is missing or not recognized.
Command GetCommandFromArgs(const CommandLine::StringVector& args) {
  if (args.size() < 1)
    return Command::CMD_UNKNOWN;

  const std::string& cmd = args[0];
  if (IsEqualNoCase(cmd, "set"))
    return Command::CMD_SET;
  else if (IsEqualNoCase(cmd, "clear"))
    return Command::CMD_CLEAR;

  LOG(ERROR) << "Not a valid command: " << cmd;
  return Command::CMD_UNKNOWN;
}

// Parse and return a boolean value from the cmd-line arguments. Returns a
// nullopt if the cmd-line value argument is missing or not a boolean.
std::optional<bool> GetBoolValueFromArgs(
    const CommandLine::StringVector& args) {
  if (args.size() >= 3) {
    const std::string& value = args[2];
    if (IsEqualNoCase(value, "true"))
      return true;
    else if (IsEqualNoCase(value, "false"))
      return false;

    LOG(ERROR) << "Not a valid boolean value: " << value;
    return std::nullopt;
  }

  return std::nullopt;
}

// Parse and return the value that is being set for the given policy. Returns
// a nullopt if the set-value is missing or is not not the right type for the
// given policy.
std::optional<bool> GetValueForSetCommand(
    const std::string& policy, const CommandLine::StringVector& args) {
  if (IsEqualNoCase(policy, kPolicyDeviceAllowBluetooth) ||
      IsEqualNoCase(policy, kShowHomeButton) ||
      IsEqualNoCase(policy, kBookmarkBarEnabled)) {
    return GetBoolValueFromArgs(args);
  }

  return std::nullopt;
}

// Handle command |cmd| for the given policy, taking any required value from
// the args list. Returns 0 in case of success or an error code otherwise.
bool HandleCommandForPolicy(Command cmd,
                            const std::string& policy,
                            const CommandLine::StringVector& args,
                            const PolicyWriter& writer) {
  DCHECK_NE(cmd, Command::CMD_UNKNOWN);

  if (!VerifyPolicyName(policy)) {
    LOG(ERROR) << "Not a valid policy name: " << policy;
    return false;
  }

  // If this is a 'set' command, parse the value to set from the args.
  std::optional<bool> set_value;
  if (cmd == Command::CMD_SET) {
    set_value = GetValueForSetCommand(policy, args);
    if (!set_value.has_value()) {
      LOG(ERROR) << "No value or invalid value specified";
      return false;
    }
  }

  bool result = false;
  if (IsEqualNoCase(policy, kPolicyDeviceAllowBluetooth)) {
    if (cmd == Command::CMD_SET)
      result = writer.SetDeviceAllowBluetooth(*set_value);
    else
      result = writer.ClearDeviceAllowBluetooth();
  } else if (IsEqualNoCase(policy, kShowHomeButton)) {
    if (cmd == Command::CMD_SET)
      result = writer.SetShowHomeButton(*set_value);
    else
      result = writer.ClearShowHomeButton();
  } else if (IsEqualNoCase(policy, kBookmarkBarEnabled)) {
    if (cmd == Command::CMD_SET)
      result = writer.SetBookmarkBarEnabled(*set_value);
    else
      result = writer.ClearBookmarkBarEnabled();
  }

  if (!result) {
    LOG(ERROR) << "Could not write policy to file.\n"
                  "You may need to run policy with sudo. "
                  "You may also need to make your rootfs writeable.";
  }

  return result;
}

}  // namespace

namespace policy_utils {

using base::CommandLine;

constexpr char PolicyTool::kChromePolicyDirPath[];
constexpr char PolicyTool::kChromiumPolicyDirPath[];

// PolicyTool::PolicyTool() : writer_(kChromePolicyDirPath) {}

PolicyTool::PolicyTool(const std::string& policy_dir_path)
    : writer_(policy_dir_path) {}

bool PolicyTool::DoCommand(const CommandLine::StringVector& args) const {
  // Args must have at least one command and one policy name.
  if (args.size() < 2)
    return false;

  Command cmd = GetCommandFromArgs(args);
  if (cmd == Command::CMD_UNKNOWN)
    return false;

  const std::string& policy = args[1];
  return HandleCommandForPolicy(cmd, policy, args, writer_);
}

const PolicyTool::PolicyList& PolicyTool::get_policies() {
  return known_policies;
}

}  // namespace policy_utils
