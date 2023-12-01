// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbfs/util.h"

#include <fcntl.h>
#include <fuse_lowlevel.h>

#include <base/strings/stringprintf.h>

namespace smbfs {
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

const FlagDef kToSetFlags[] = {
    FLAG_DEF(FUSE_SET_ATTR_MODE),      FLAG_DEF(FUSE_SET_ATTR_UID),
    FLAG_DEF(FUSE_SET_ATTR_GID),       FLAG_DEF(FUSE_SET_ATTR_SIZE),
    FLAG_DEF(FUSE_SET_ATTR_ATIME),     FLAG_DEF(FUSE_SET_ATTR_MTIME),
    FLAG_DEF(FUSE_SET_ATTR_ATIME_NOW), FLAG_DEF(FUSE_SET_ATTR_MTIME_NOW),
};

template <size_t N>
std::string FlagsToString(const FlagDef (&defs)[N], int flags) {
  if (!flags) {
    return "0";
  }

  std::string str;
  for (const auto& def : defs) {
    if (flags & def.flag) {
      if (!str.empty()) {
        str.append("|");
      }
      str.append(def.name);
      flags &= ~def.flag;
    }
  }
  if (flags) {
    if (!str.empty()) {
      str.append("|");
    }
    str.append(base::StringPrintf("0x%x", flags));
  }
  return str;
}

}  // namespace

std::string OpenFlagsToString(int flags) {
  std::string str;
  switch (flags & O_ACCMODE) {
    case O_RDONLY:
      str = "O_RDONLY";
      break;
    case O_WRONLY:
      str = "O_WRONLY";
      break;
    case O_RDWR:
      str = "O_RDWR";
      break;
    default:
      str = "INVALID_OPEN_MODE";
      break;
  }
  flags &= ~O_ACCMODE;
  if (flags) {
    str.append("|");
    str.append(FlagsToString(kOpenFlags, flags));
  }

  return str;
}

std::string ToSetFlagsToString(int flags) {
  return FlagsToString(kToSetFlags, flags);
}

std::string IpAddressToString(const std::vector<uint8_t>& address) {
  if (address.size() != 4) {
    return {};
  }

  return base::StringPrintf("%u.%u.%u.%u", address[0], address[1], address[2],
                            address[3]);
}

}  // namespace smbfs
