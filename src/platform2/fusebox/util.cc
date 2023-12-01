// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "fusebox/util.h"

#include <fcntl.h>
#include <fuse_lowlevel.h>

#include <base/strings/stringprintf.h>

namespace {

struct FlagDef {
  const int flag;
  const char* name;
};

#define FLAG_DEF(f) \
  { f, #f }

const FlagDef kOpenFlags[] = {
    FLAG_DEF(O_APPEND),   FLAG_DEF(O_ASYNC),  FLAG_DEF(O_CLOEXEC),
    FLAG_DEF(O_CREAT),    FLAG_DEF(O_DIRECT), FLAG_DEF(O_DIRECTORY),
    FLAG_DEF(O_DSYNC),    FLAG_DEF(O_EXCL),   FLAG_DEF(O_LARGEFILE),
    FLAG_DEF(O_NOATIME),  FLAG_DEF(O_NOCTTY), FLAG_DEF(O_NOFOLLOW),
    FLAG_DEF(O_NONBLOCK), FLAG_DEF(O_PATH),   FLAG_DEF(O_SYNC),
    FLAG_DEF(O_TMPFILE),  FLAG_DEF(O_TRUNC),
};

const FlagDef kFuseToSetFlags[] = {
    FLAG_DEF(FUSE_SET_ATTR_MODE),      FLAG_DEF(FUSE_SET_ATTR_UID),
    FLAG_DEF(FUSE_SET_ATTR_GID),       FLAG_DEF(FUSE_SET_ATTR_SIZE),
    FLAG_DEF(FUSE_SET_ATTR_ATIME),     FLAG_DEF(FUSE_SET_ATTR_MTIME),
    FLAG_DEF(FUSE_SET_ATTR_ATIME_NOW), FLAG_DEF(FUSE_SET_ATTR_MTIME_NOW),
};

template <size_t N>
std::string FlagsToString(const FlagDef (&defs)[N], int flags) {
  std::string flags_string;

  if (!flags)
    return "0";

  for (const auto& d : defs) {
    if (flags & d.flag) {
      if (!flags_string.empty())
        flags_string.append("|");
      flags_string.append(d.name);
      flags &= ~d.flag;
    }
  }

  if (flags) {
    if (!flags_string.empty())
      flags_string.append("|");
    flags_string.append(base::StringPrintf("0x%x", flags));
  }

  return flags_string;
}

}  // namespace

std::string OpenFlagsToString(int flags) {
  std::string open_flags_string;

  switch (flags & O_ACCMODE) {  // Only three things, ...
    case O_RDONLY:
      open_flags_string = "O_RDONLY";
      break;
    case O_WRONLY:
      open_flags_string = "O_WRONLY";
      break;
    case O_RDWR:
      open_flags_string = "O_RDWR";
      break;
    default:
      open_flags_string = "INVALID_O_ACCMODE_FLAG";
      break;
  }

  flags &= ~O_ACCMODE;
  if (flags) {
    open_flags_string.append("|");
    open_flags_string.append(FlagsToString(kOpenFlags, flags));
  }

  return open_flags_string;
}

std::string ToSetFlagsToString(int flags) {
  return FlagsToString(kFuseToSetFlags, flags);
}
