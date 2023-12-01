// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/system/system_utilities_impl.h"

#include <sys/utsname.h>

namespace diagnostics {

SystemUtilitiesImpl::SystemUtilitiesImpl() = default;
SystemUtilitiesImpl::~SystemUtilitiesImpl() = default;

int SystemUtilitiesImpl::Uname(struct utsname* buf) {
  return uname(buf);
}

}  // namespace diagnostics
