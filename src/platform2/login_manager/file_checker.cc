// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/file_checker.h"

#include <base/files/file_path.h>
#include <base/files/file_util.h>

namespace login_manager {

FileChecker::FileChecker(const base::FilePath& filename)
    : filename_(filename) {}

FileChecker::~FileChecker() {}

bool FileChecker::exists() {
  return base::PathExists(filename_);
}

}  // namespace login_manager
