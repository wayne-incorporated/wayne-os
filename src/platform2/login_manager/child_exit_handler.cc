// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/child_exit_handler.h"

#include <string.h>

#include <base/strings/stringprintf.h>

namespace login_manager {

// static
std::string ChildExitHandler::GetExitDescription(const siginfo_t& status) {
  return status.si_code == CLD_EXITED
             ? base::StringPrintf("exit code %d", status.si_status)
             : base::StringPrintf("signal %d (%s)", status.si_status,
                                  strsignal(status.si_status));
}

}  // namespace login_manager
