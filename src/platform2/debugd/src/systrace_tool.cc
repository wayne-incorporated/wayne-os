// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/systrace_tool.h"

#include <unistd.h>

#include <string>
#include <vector>

#include <base/strings/string_split.h>
#include <brillo/process/process.h>

#include "debugd/src/constants.h"
#include "debugd/src/helper_utils.h"
#include "debugd/src/process_with_output.h"
#include "debugd/src/sandboxed_process.h"

namespace debugd {

namespace {

const char kSystraceHelper[] = "systrace.sh";

void AddCategoryArgs(ProcessWithOutput* p, const std::string& categories) {
  std::vector<std::string> pieces = base::SplitString(
      categories, " ", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
  for (const auto& category : pieces)
    p->AddArg(category);
}

}  // namespace

std::string SystraceTool::Start(const std::string& categories) {
  std::string path;
  if (!GetHelperPath(kSystraceHelper, &path))
    return "";

  ProcessWithOutput p;
  // this tool needs to reach into /sys/kernel/debug to enable/disable tracing
  p.SandboxAs(SandboxedProcess::kDefaultUser, kDebugfsGroup);
  p.Init();
  p.AddArg(path);
  p.AddArg("start");
  AddCategoryArgs(&p, categories);
  p.Run();
  std::string out;
  p.GetOutput(&out);
  return out;
}

void SystraceTool::Stop(const base::ScopedFD& outfd) {
  std::string path;
  if (!GetHelperPath(kSystraceHelper, &path))
    return;

  SandboxedProcess p;
  p.SandboxAs(SandboxedProcess::kDefaultUser, kDebugfsGroup);
  p.Init();
  p.AddArg(path);
  p.AddArg("stop");
  // trace data is sent to stdout and not across dbus
  p.BindFd(outfd.get(), STDOUT_FILENO);
  p.Run();
}

std::string SystraceTool::Status() {
  std::string path;
  if (!GetHelperPath(kSystraceHelper, &path))
    return "";

  ProcessWithOutput p;
  p.SandboxAs(SandboxedProcess::kDefaultUser, kDebugfsGroup);
  p.Init();
  p.AddArg(path);
  p.AddArg("status");
  p.Run();
  std::string out;
  p.GetOutput(&out);
  return out;
}

}  // namespace debugd
