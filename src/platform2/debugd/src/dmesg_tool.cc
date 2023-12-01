// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// This tool is used for getting dmesg information through debugd.

#include "debugd/src/dmesg_tool.h"

#include <vector>

#include <base/containers/span.h>
#include <base/strings/strcat.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>

#include "debugd/src/error_utils.h"
#include "debugd/src/process_with_output.h"
#include "debugd/src/variant_utils.h"
#include "linux/capability.h"

namespace {

constexpr const char kDmesgPath[] = "/bin/dmesg";
constexpr const char kErrorPath[] = "org.chromium.debugd.error.DmesgTool";

constexpr const char kInvalidOption[] = "<invalid option>";
constexpr const char kNonzeroExitStatus[] =
    "<process exited with nonzero status>";
constexpr const char kProcessInitFailed[] = "<process init failed>";

}  // namespace

namespace debugd {
// static
void DmesgTool::Tail(uint32_t lines, std::string& output) {
  if (lines <= 0) {
    output.clear();
    return;
  }

  if (output.empty()) {
    return;
  }

  std::vector<base::StringPiece> split = base::SplitStringPiece(
      output, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);

  // When the last character is \n, we get an extra blank line at the end which
  // we don't actually want. (We want other blank lines, but not the extra blank
  // at the end.)
  bool had_ending_newline = false;
  if (output.back() == '\n') {
    split.pop_back();
    had_ending_newline = true;
  }

  if (split.size() <= lines) {
    return;
  }

  base::span<base::StringPiece> desired_lines(
      split.begin() + (split.size() - lines), lines);

  output = base::StrCat({base::JoinString(desired_lines, "\n"),
                         (had_ending_newline ? "\n" : "")});
}

bool DmesgTool::CallDmesg(const brillo::VariantDictionary& options,
                          brillo::ErrorPtr* error,
                          std::string* output) {
  ProcessWithOutput process;

  // WARNING: CAP_TO_MASK() produces bad results when used with values >=32.
  process.SetCapabilities(1ULL << CAP_SYSLOG);
  if (!process.Init()) {
    *output = kProcessInitFailed;
    DEBUGD_ADD_ERROR(error, kErrorPath, kProcessInitFailed);
    return false;
  }

  process.AddArg(kDmesgPath);

  if (!AddBoolOption(&process, options, "show-delta", "-d", error) ||
      !AddBoolOption(&process, options, "human", "--human", error) ||
      !AddBoolOption(&process, options, "kernel", "-k", error) ||
      !AddBoolOption(&process, options, "color", "--color=always", error) ||
      !AddBoolOption(&process, options, "force-prefix", "-p", error) ||
      !AddBoolOption(&process, options, "raw", "-r", error) ||
      !AddBoolOption(&process, options, "ctime", "-T", error) ||
      !AddBoolOption(&process, options, "notime", "-t", error) ||
      !AddBoolOption(&process, options, "userspace", "-u", error) ||
      !AddBoolOption(&process, options, "decode", "-x", error)) {
    *output = kInvalidOption;
    DEBUGD_ADD_ERROR(error, kErrorPath, kInvalidOption);
    return false;
  }

  if (process.Run() != 0) {
    *output = kNonzeroExitStatus;
    DEBUGD_ADD_ERROR(error, kErrorPath, kNonzeroExitStatus);
    return false;
  }

  process.GetOutput(output);

  uint32_t lines = 0;
  ParseResult result = GetOption(options, "tail", &lines, error);
  if (result == ParseResult::PARSE_ERROR) {
    *output = "<invalid option to tail>";
    return false;  // DEBUGD_ADD_ERROR is already called.
  }
  if (result == ParseResult::PARSED) {
    Tail(lines, *output);
  }

  return true;
}

}  // namespace debugd
