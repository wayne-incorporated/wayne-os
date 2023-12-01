// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FUSEBOX_MAKE_STAT_H_
#define FUSEBOX_MAKE_STAT_H_

#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <string>

#include "fusebox/proto_bindings/fusebox.pb.h"

namespace fusebox {

// File system entry UID: user chronos.
constexpr uid_t kChronosUID = 1000;

// File system entry GID: group chronos-access.
constexpr uid_t kChronosAccessGID = 1001;

// FUSE response timeouts.
constexpr double kStatTimeoutSeconds = 5.0;
constexpr double kEntryTimeoutSeconds = 5.0;

// Returns true if |mode| type is allowed.
bool IsAllowedStatMode(mode_t mode, mode_t allowed = S_IFREG | S_IFDIR);

// Returns |mode| with synthesized permission bits.
mode_t MakeStatModeBits(mode_t mode, bool read_only = false);

// Returns stat with .st_mode |mode| and time fields set to |time|.
struct stat MakeTimeStat(mode_t mode, time_t time = std::time(nullptr));

// Returns an inode |ino| stat with synthesized permission bits.
struct stat MakeStat(ino_t ino, const struct stat& s, bool read_only = false);

// Returns an inode |ino| stat with synthesized permission bits.
struct stat MakeStatFromProto(ino_t ino, const DirEntryProto& proto);

// Returns mode string.
std::string StatModeToString(mode_t mode);

}  // namespace fusebox

#endif  // FUSEBOX_MAKE_STAT_H_
