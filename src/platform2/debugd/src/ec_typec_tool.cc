// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/ec_typec_tool.h"

#include <vector>

#include <base/files/file_path.h>
#include <base/strings/stringprintf.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <brillo/key_value_store.h>
#include <re2/re2.h>

#include "debugd/src/ectool_util.h"
#include "debugd/src/error_utils.h"

namespace {

constexpr char kErrorPath[] = "org.chromium.debugd.EcTypeCToolError";
constexpr char kSandboxDirPath[] = "/usr/share/policy/";
constexpr char kRunAs[] = "typecd_ec";
constexpr char kMuxInfoPortRegex[] = R"(Port (\d):(.+))";
constexpr char kHpdGpioStr[] = "usb_c%u_hpd";

// Returns the ectool policy file corresponding to the provided
// |ectool_command|.
std::string GetEctoolPolicyFile(const std::string& ectool_command) {
  return base::StringPrintf("ectool_%s-seccomp.policy", ectool_command.c_str());
}

// Helper function to retrieve an integer value corresponding to a key in a
// KeyValueStore.
bool GetIntValFromKvStore(const brillo::KeyValueStore& kv,
                          const std::string& key,
                          int* val) {
  std::string val_str;
  if (!kv.GetString(key, &val_str))
    return false;

  base::TrimWhitespaceASCII(val_str, base::TRIM_ALL, &val_str);
  return base::StringToInt(val_str, val);
}

}  // namespace

namespace debugd {

std::string EcTypeCTool::GetInventory() {
  std::string output;
  const auto seccomp_policy_path =
      base::FilePath(kSandboxDirPath).Append(GetEctoolPolicyFile("typec"));
  std::vector<std::string> ectool_args = {"inventory"};

  brillo::ErrorPtr error;
  if (!RunEctoolWithArgs(&error, seccomp_policy_path, ectool_args, kRunAs,
                         &output))
    output.clear();

  return output;
}

bool EcTypeCTool::EnterMode(brillo::ErrorPtr* error,
                            uint32_t port_num,
                            uint32_t mode,
                            std::string* output) {
  const auto seccomp_policy_path =
      base::FilePath(kSandboxDirPath).Append(GetEctoolPolicyFile("typec"));

  std::vector<std::string> ectool_args = {"typeccontrol"};
  ectool_args.push_back(base::StringPrintf("%u", port_num));
  // 2nd argument is '2' for enter mode.
  ectool_args.push_back("2");
  ectool_args.push_back(base::StringPrintf("%u", mode));

  if (!RunEctoolWithArgs(error, seccomp_policy_path, ectool_args, kRunAs,
                         output))
    return false;  // DEBUGD_ADD_ERROR is already called.

  return true;
}

bool EcTypeCTool::ExitMode(brillo::ErrorPtr* error,
                           uint32_t port_num,
                           std::string* output) {
  const auto seccomp_policy_path =
      base::FilePath(kSandboxDirPath).Append(GetEctoolPolicyFile("typec"));

  std::vector<std::string> ectool_args = {"typeccontrol"};
  ectool_args.push_back(base::StringPrintf("%u", port_num));
  // 2nd argument is '0' for exit mode.
  ectool_args.push_back("0");

  if (!RunEctoolWithArgs(error, seccomp_policy_path, ectool_args, kRunAs,
                         output))
    return false;  // DEBUGD_ADD_ERROR is already called.

  return true;
}

bool EcTypeCTool::DpState(brillo::ErrorPtr* error,
                          uint32_t port_num,
                          bool* output) {
  const auto seccomp_policy_path =
      base::FilePath(kSandboxDirPath).Append(GetEctoolPolicyFile("typec"));

  std::vector<std::string> ectool_args = {"usbpdmuxinfo"};
  std::string result;

  if (!RunEctoolWithArgs(error, seccomp_policy_path, ectool_args, kRunAs,
                         &result))
    return false;  // DEBUGD_ADD_ERROR is already called.

  return ParseDpState(error, port_num, result, output);
}

bool EcTypeCTool::ParseDpState(brillo::ErrorPtr* error,
                               uint32_t port_num,
                               const std::string& input,
                               bool* output) {
  std::vector<std::string> ports =
      base::SplitString(input, "\n", base::WhitespaceHandling::TRIM_WHITESPACE,
                        base::SplitResult::SPLIT_WANT_ALL);
  for (const auto& str : ports) {
    int port_num_ret;
    std::string mux_str;
    if (!RE2::FullMatch(str, kMuxInfoPortRegex, &port_num_ret, &mux_str) ||
        port_num_ret != port_num)
      continue;

    base::TrimWhitespaceASCII(mux_str, base::TRIM_ALL, &mux_str);
    std::vector<std::string> kv_pairs = base::SplitString(
        mux_str, " ", base::WhitespaceHandling::TRIM_WHITESPACE,
        base::SplitResult::SPLIT_WANT_ALL);
    for (const auto& pair : kv_pairs) {
      brillo::KeyValueStore kv;
      kv.LoadFromString(pair);

      int dp;
      if (!GetIntValFromKvStore(kv, "DP", &dp))
        continue;

      *output = dp;
      return true;
    }
  }

  DEBUGD_ADD_ERROR(error, kErrorPath, "DP state unavailable on this system.");
  return false;
}

bool EcTypeCTool::HpdState(brillo::ErrorPtr* error,
                           uint32_t port_num,
                           bool* output) {
  const auto seccomp_policy_path =
      base::FilePath(kSandboxDirPath).Append(GetEctoolPolicyFile("typec"));

  std::string result;
  std::vector<std::string> ectool_args = {"gpioget"};
  ectool_args.push_back(base::StringPrintf(kHpdGpioStr, port_num));

  if (!RunEctoolWithArgs(error, seccomp_policy_path, ectool_args, kRunAs,
                         &result))
    return false;  // DEBUGD_ADD_ERROR is already called.

  return ParseHpdState(error, port_num, result, output);
}

bool EcTypeCTool::ParseHpdState(brillo::ErrorPtr* error,
                                uint32_t port_num,
                                const std::string& input,
                                bool* output) {
  brillo::KeyValueStore kv;
  kv.LoadFromString(input);
  auto keys = kv.GetKeys();
  // There should only be 1 key-value pair.
  if (keys.size() != 1) {
    DEBUGD_ADD_ERROR(error, kErrorPath,
                     "Duplicate HPD GPIOs found on this system.");
    return false;
  }

  auto expected_key =
      std::string("GPIO ") + base::StringPrintf(kHpdGpioStr, port_num);
  if (keys[0] != expected_key) {
    DEBUGD_ADD_ERROR(error, kErrorPath,
                     "GPIO returned is different than the one requested.");
    return false;
  }

  int hpd;
  if (!GetIntValFromKvStore(kv, keys[0], &hpd)) {
    DEBUGD_ADD_ERROR(error, kErrorPath,
                     "Unable to parse HPD state on this system.");
    return false;
  }

  *output = hpd;
  return true;
}

}  // namespace debugd
