// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/platform/platform_impl.h"

#include <base/files/file_util.h>

namespace hwsec {

bool PlatformImpl::ReadFileToString(const base::FilePath& path,
                                    std::string* contents) {
  return base::ReadFileToString(path, contents);
}

}  // namespace hwsec
