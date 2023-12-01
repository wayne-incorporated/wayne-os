// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/subprocess_tool.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/containers/contains.h>

#include "debugd/src/error_utils.h"

namespace debugd {

namespace {

const char kErrorNoSuchProcess[] = "org.chromium.debugd.error.NoSuchProcess";

}  // namespace

ProcessWithId* SubprocessTool::CreateProcess(
    bool sandboxed,
    bool access_root_mount_ns,
    const std::vector<std::string>& minijail_extra_args) {
  auto process = std::make_unique<ProcessWithId>();
  if (!sandboxed)
    process->DisableSandbox();

  if (access_root_mount_ns)
    process->AllowAccessRootMountNamespace();

  if (!process->Init(minijail_extra_args))
    return nullptr;

  ProcessWithId* process_ptr = process.get();
  if (RecordProcess(std::move(process)))
    return process_ptr;

  return nullptr;
}

ProcessWithId* SubprocessTool::CreateProcess(bool sandboxed,
                                             bool access_root_mount_ns) {
  return CreateProcess(sandboxed, access_root_mount_ns, {});
}

bool SubprocessTool::RecordProcess(std::unique_ptr<ProcessWithId> process) {
  if (base::Contains(processes_, process->id()))
    return false;

  processes_[process->id()] = std::move(process);
  return true;
}

bool SubprocessTool::Stop(const std::string& handle, brillo::ErrorPtr* error) {
  if (handle.empty()) {
    for (auto const& process : processes_) {
      ProcessWithId* process_ptr = process.second.get();
      process_ptr->KillProcessGroup();
    }
    processes_.clear();
    return true;
  }
  if (processes_.count(handle) != 1) {
    DEBUGD_ADD_ERROR(error, kErrorNoSuchProcess, handle.c_str());
    return false;
  }
  ProcessWithId* process_ptr = processes_[handle].get();
  process_ptr->KillProcessGroup();
  processes_.erase(handle);
  return true;
}

}  // namespace debugd
