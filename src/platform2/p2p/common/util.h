// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P2P_COMMON_UTIL_H_
#define P2P_COMMON_UTIL_H_

#include <base/files/file_path.h>

namespace p2p {

namespace util {

// Sets up the libbase/libchrome logging infrastructure (e.g. LOG(INFO))
// to use the standard syslog mechanism (e.g. typically
// /var/log/messages). Each log message will be prepended by
// |program_name| and, if |include_pid| is true, the process id.
void SetupSyslog(const char* program_name, bool include_pid);

// Checks if xattr is supported in the directory specified by
// |dir_path| which must be writable. Returns true if the feature is
// supported, false if not or if an error occured.
bool IsXAttrSupported(const base::FilePath& dir_path);

}  // namespace util

}  // namespace p2p

#endif  // P2P_COMMON_UTIL_H_
