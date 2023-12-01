// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/route_tool.h"

#include <map>

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

std::vector<std::string> RouteTool::GetRoutes(
    const brillo::VariantDictionary& options) {
  std::vector<std::string> full_result, cmd_result;

  std::string ip_version = "-4";
  if (brillo::GetVariantValueOrDefault<bool>(options, "v6"))
    ip_version = "-6";

  RunOneIPCommand(&full_result, {ip_version, "rule", "list"});

  if (brillo::GetVariantValueOrDefault<bool>(options, "all")) {
    // Print all routes of all routing tables.
    RunOneIPCommand(&cmd_result, {ip_version, "route", "show", "table", "all"});
    full_result.push_back("");
    full_result.insert(full_result.end(), cmd_result.begin(), cmd_result.end());
  }

  // Always print the main table first.  Ignore local and default since
  // they'll just confuse the user.
  RunOneIPCommand(&cmd_result, {ip_version, "route", "show", "table", "main"});
  full_result.push_back("");
  full_result.insert(full_result.end(), cmd_result.begin(), cmd_result.end());

  // Multiple routing policy rules can reference the same table, so keep
  // a map to make sure each table is only printed once.
  std::map<int, bool> table_map;
  for (auto line : full_result) {
    base::TrimWhitespaceASCII(line, base::TRIM_ALL, &line);

    const std::string prefix("lookup ");
    size_t offset = line.rfind(prefix);
    if (offset != std::string::npos) {
      int table_id;
      if (base::StringToInt(line.substr(offset + prefix.size()), &table_id) &&
          table_map.find(table_id) == table_map.end()) {
        table_map[table_id] = true;
        RunOneIPCommand(&cmd_result, {ip_version, "route", "show", "table",
                                      base::NumberToString(table_id)});
        full_result.push_back("");
        full_result.insert(full_result.end(), cmd_result.begin(),
                           cmd_result.end());
      }
    }
  }

  return full_result;
}

}  // namespace debugd
