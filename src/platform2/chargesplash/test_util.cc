// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include "chargesplash/test_util.h"

namespace {

std::string sysroot_ = "";  // NOLINT(runtime/string)

}  // namespace

namespace chargesplash {

std::string GetPath(const std::string& path) {
  return sysroot_ + path;
}

void SetSysrootForTesting(const std::string& sysroot) {
  sysroot_ = sysroot;
}

}  // namespace chargesplash
