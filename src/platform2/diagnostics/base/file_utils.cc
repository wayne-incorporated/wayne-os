// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/base/file_utils.h"

#include <base/files/file_util.h>
#include <base/strings/string_util.h>

namespace diagnostics {

template <>
bool ReadAndTrimString<std::string>(const base::FilePath& file_path,
                                    std::string* out) {
  DCHECK(out);

  if (!base::ReadFileToString(file_path, out))
    return false;

  base::TrimWhitespaceASCII(*out, base::TRIM_ALL, out);
  return true;
}

}  // namespace diagnostics
