// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_minidiag/utils.h"

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_util.h>

namespace cros_minidiag {
bool GetPrevElogLastLine(const base::FilePath& file, std::string& last_line) {
  last_line.clear();
  // Since we cannot make assumptions about the content of this file which has a
  // volatile path and could be corrupted or modified, we have to ensure the
  // file size is not suspiciously large.
  if (!base::ReadFileToStringWithMaxSize(file, &last_line, kMaxFileSize)) {
    PLOG(ERROR) << "Failed to read file or file size suspiciously large: "
                << file.value();
    last_line.clear();
    return false;
  }
  if (!base::IsStringASCII(last_line)) {
    PLOG(ERROR) << "Skip non-ASCII last_line file: " << file.value();
    last_line.clear();
    return false;
  }
  // Trim the last_line string to be compatible with the legacy shell code which
  // contains a trailing newline.
  base::TrimWhitespaceASCII(last_line, base::TRIM_TRAILING, &last_line);
  return true;
}
}  // namespace cros_minidiag
