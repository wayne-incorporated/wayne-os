// Copyright (c) 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/child_job.h"

#include <sysexits.h>  // For exit code defines (EX__MAX, etc).

namespace login_manager {

const int ChildJobInterface::kCantSetUid = EX__MAX + 1;
const int ChildJobInterface::kCantSetGid = EX__MAX + 2;
const int ChildJobInterface::kCantSetGroups = EX__MAX + 3;
const int ChildJobInterface::kCantSetEnv = EX__MAX + 4;
const int ChildJobInterface::kCantExec = EX_OSERR;

};  // namespace login_manager
