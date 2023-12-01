// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_TIMEZONE_TZIF_PARSER_H_
#define LIBBRILLO_BRILLO_TIMEZONE_TZIF_PARSER_H_

#include <optional>
#include <string>

#include <base/files/file_path.h>
#include <brillo/brillo_export.h>

namespace brillo {

namespace timezone {

// GetPosixTimezone takes a path to a tzfile, and returns the POSIX timezone in
// a string. See 'man tzfile' for more info on the format. If |tzif_path| is a
// relative path, it will be appended to /usr/share/zoneinfo/, otherwise
// |tzif_path| as an absolute path will be used directly.
std::optional<std::string> BRILLO_EXPORT
GetPosixTimezone(const base::FilePath& tzif_path);

}  // namespace timezone

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_TIMEZONE_TZIF_PARSER_H_
