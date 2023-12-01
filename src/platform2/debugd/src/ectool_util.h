// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_ECTOOL_UTIL_H_
#define DEBUGD_SRC_ECTOOL_UTIL_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <brillo/errors/error.h>

namespace debugd {

bool RunEctoolWithArgs(brillo::ErrorPtr* error,
                       const base::FilePath& seccomp_policy_path,
                       const std::vector<std::string> ectool_args,
                       const std::string& user,
                       std::string* output);

}  // namespace debugd

#endif  // DEBUGD_SRC_ECTOOL_UTIL_H_
