// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef KERBEROS_PLATFORM_HELPER_H_
#define KERBEROS_PLATFORM_HELPER_H_

#include <optional>
#include <string>

#include <base/files/scoped_file.h>

namespace base {
class FilePath;
}

namespace kerberos {

// Reads the whole contents of the file descriptor |fd| into the returned
// string. If fd is a blocking pipe this call will block until the pipe is
// closed. Returns nullopt if the pipe could not be read or some limit was
// exceeded (see code).
std::optional<std::string> ReadPipeToString(int fd);

// Creates a non-blocking pipe and writes the given string to it. |str| must be
// small enough to fit into the pipe buffer. Returns base::ScopedFD() on error.
base::ScopedFD WriteStringToPipe(const std::string& str);

}  // namespace kerberos

#endif  // KERBEROS_PLATFORM_HELPER_H_
