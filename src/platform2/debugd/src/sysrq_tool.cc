// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/sysrq_tool.h"

#include <fcntl.h>
#include <unistd.h>

#include "debugd/src/error_utils.h"

namespace debugd {

namespace {

const char kErrorSysrq[] = "org.chromium.debugd.error.sysrq";

}  // namespace

bool SysrqTool::LogKernelTaskStates(brillo::ErrorPtr* error) {
  int sysrq_trigger = open("/proc/sysrq-trigger", O_WRONLY | O_CLOEXEC);
  if (sysrq_trigger < 0) {
    DEBUGD_ADD_PERROR(error, kErrorSysrq, "open");
    return false;
  }
  ssize_t written = write(sysrq_trigger, "t", 1);
  close(sysrq_trigger);
  if (written < 1) {
    DEBUGD_ADD_PERROR(error, kErrorSysrq, "write");
    return false;
  }
  return true;
}

}  // namespace debugd
