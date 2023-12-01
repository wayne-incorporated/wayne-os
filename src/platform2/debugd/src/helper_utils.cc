// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/helper_utils.h"

#include <inttypes.h>
#include <limits.h>
#include <vector>

#include <base/strings/stringprintf.h>

namespace debugd {

bool GetHelperPath(const std::string& relative_path, std::string* full_path) {
  const char* helpers_dir = "/usr/libexec/debugd/helpers";
  std::string path =
      base::StringPrintf("%s/%s", helpers_dir, relative_path.c_str());

  if (path.length() >= PATH_MAX)
    return false;

  *full_path = path;
  return true;
}

}  // namespace debugd
