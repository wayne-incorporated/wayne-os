// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/ipaddrs_tool.h"

#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <brillo/process/process.h>

#include "debugd/src/process_with_output.h"

namespace debugd {

namespace {

const char kIpTool[] = "/bin/ip";

bool RunOneIPCommand(std::vector<std::string>* result,
                     const std::vector<std::string>& argv) {
  ProcessWithOutput p;
  if (!p.Init()) {
    result->push_back("[ ProcessWithOutput::Init() failed ]");
    return false;
  }

  p.AddArg(kIpTool);
  for (const auto& arg : argv) {
    p.AddArg(arg);
  }

  if (p.Run()) {
    result->push_back("[ ProcessWithOutput::Run() failed ]");
    return false;
  }

  p.GetOutputLines(result);

  // GetOutputLines() overwrites |result|, so the heading needs to be
  // inserted afterward.
  result->insert(
      result->begin(),
      base::StringPrintf("[ ip %s ]", base::JoinString(argv, " ").c_str()));
  return true;
}

}  // namespace

std::vector<std::string> IpAddrsTool::GetIpAddresses(
    const brillo::VariantDictionary& options) {
  std::vector<std::string> full_result, cmd_result;

  std::string ip_version = "-4";
  if (brillo::GetVariantValueOrDefault<bool>(options, "v6"))
    ip_version = "-6";

  RunOneIPCommand(&full_result, {ip_version, "addr", "show"});

  return full_result;
}

}  // namespace debugd
