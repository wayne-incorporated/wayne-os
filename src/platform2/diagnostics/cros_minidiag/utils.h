// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_MINIDIAG_UTILS_H_
#define DIAGNOSTICS_CROS_MINIDIAG_UTILS_H_

#include <base/files/file_util.h>

#include <string>

namespace cros_minidiag {
// Set a hard limit, 64KB, for the maximum file size of elog-last-line.
// This is to prevent reading from potentially malicious files that may have
// been tampered with.
inline constexpr const int64_t kMaxFileSize = 65536;

// Helper function to read the elog-last-line from the specific file and trim it
// to ensure no trailing spaces or newlines.
// In case of error or the file size exceeds kMaxFileSize, the function returns
// false and the last_line is cleared.
[[nodiscard]] bool GetPrevElogLastLine(const base::FilePath& file,
                                       std::string& last_line);
}  // namespace cros_minidiag
#endif  // DIAGNOSTICS_CROS_MINIDIAG_UTILS_H_
