// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// MountEntry objects represent entries in the list of mounts obtained from
// /proc/<pid>/mounts.

#ifndef SECANOMALYD_MOUNT_ENTRY_H_
#define SECANOMALYD_MOUNT_ENTRY_H_

#include <map>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/strings/string_piece.h>

#include "secanomalyd/system_context.h"

namespace secanomalyd {

using ContextChecker = base::RepeatingCallback<bool(const SystemContext&)>;
// For every known mount there is a callback that ensures mounts are only
// ignored in the right context (e.g. only ignored if non-persistent).
const std::map<base::FilePath, ContextChecker> kKnownMounts{
    // TODO(b/219574442): Make /run/arc/shared_mounts/data not W+X.
    // /run/arc/shared_mounts/data exists for less than a second during the
    // setup phase of ARC++ (only applicable in container based systems).
    {base::FilePath("/run/arc/shared_mounts/data"),
     base::BindRepeating([](const SystemContext& context) {
       return (context.IsUserLoggedIn() &&
               !context.IsMountPersistent(
                   base::FilePath("/run/arc/shared_mounts/data")));
     })},
};

class MountEntry;
using MountEntryMap = std::map<base::FilePath, MountEntry>;

class MountEntry {
 public:
  MountEntry() : src_{}, dest_{}, type_{}, opts_{} {}

  explicit MountEntry(base::StringPiece mount_str);

  // Copying the private fields is fine.
  MountEntry(const MountEntry& other) = default;
  MountEntry& operator=(const MountEntry& other) = default;

  // TODO(jorgelo): Implement move constructor so that we can use emplace().

  bool IsWX() const;
  bool IsUsbDriveOrArchive() const;
  bool IsDestInUsrLocal() const;
  bool IsNamespaceBindMount() const;

  // IsKnownMount() allows us to avoid polluting our reports with W+X mounts
  // that we know are not high-risk. Each mount that we allow is covered by
  // a bug tracking its fix.
  bool IsKnownMount(const SystemContext& context) const;

  const base::FilePath& src() const { return src_; }
  const base::FilePath& dest() const { return dest_; }
  const std::string& type() const { return type_; }

  // This will return a string of the form "<src> <dest> <type> <opt1>,...".
  std::string FullDescription() const;

 private:
  base::FilePath src_;
  base::FilePath dest_;
  std::string type_;
  std::vector<std::string> opts_;
};

}  // namespace secanomalyd

#endif  // SECANOMALYD_MOUNT_ENTRY_H_
