// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "secanomalyd/mount_entry.h"

#include <algorithm>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <re2/re2.h>

namespace secanomalyd {

namespace {
// These paths can be sources of removable drive or archive mounts.
const std::vector<base::FilePath> kSrcPathsToFilter = {
    base::FilePath("/home/chronos"),
    base::FilePath("/media/archive"),
    base::FilePath("/media/fuse"),
    base::FilePath("/media/removable"),
    base::FilePath("/run/arc/sdcard/write/emulated/0"),
};

// These paths can be destinations for removable drive or archive mounts.
const std::vector<base::FilePath> kDestPathsToFilter = {
    base::FilePath("/media/archive"),
    base::FilePath("/media/fuse"),
    base::FilePath("/media/removable"),
};

const base::FilePath kUsrLocal = base::FilePath("/usr/local");

const re2::RE2 sha1_re("[a-f0-9]{40}");

}  // namespace

MountEntry::MountEntry(base::StringPiece mount_str) {
  // These entries are of the form:
  // /dev/root / ext2 rw,seclabel,relatime 0 0
  std::vector<base::StringPiece> fields =
      base::SplitStringPiece(mount_str, base::kWhitespaceASCII,
                             base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  src_ = base::FilePath(fields[0]);

  // If the mount includes a SHA1 hash, replace the hash with a placeholder.
  // This will allow grouping equivalent mounts in the same crash bucket,
  // even if their paths are not equal.
  // Moreover, these SHA1 hashes can be salted hashes of the user's email
  // address which is PII.
  std::string str_dest = std::string(fields[1]);
  re2::RE2::Replace(&str_dest, sha1_re, "<hash>");

  dest_ = base::FilePath(str_dest);
  type_ = std::string(fields[2]);

  opts_ = base::SplitString(fields[3], ",", base::TRIM_WHITESPACE,
                            base::SPLIT_WANT_NONEMPTY);
}

bool MountEntry::IsWX() const {
  return std::find(opts_.begin(), opts_.end(), "rw") != opts_.end() &&
         std::find(opts_.begin(), opts_.end(), "noexec") == opts_.end();
}

bool MountEntry::IsUsbDriveOrArchive() const {
  for (const auto& src_path_to_filter : kSrcPathsToFilter) {
    if (src_path_to_filter.IsParent(src_)) {
      return true;
    }
  }

  for (const auto& dest_path_to_filter : kDestPathsToFilter) {
    if (dest_path_to_filter.IsParent(dest_)) {
      return true;
    }
  }

  return false;
}

bool MountEntry::IsDestInUsrLocal() const {
  return kUsrLocal == this->dest() || kUsrLocal.IsParent(this->dest());
}

bool MountEntry::IsNamespaceBindMount() const {
  return this->type() == "nsfs";
}

bool MountEntry::IsKnownMount(const SystemContext& context) const {
  auto known_mount_entry = kKnownMounts.find(this->dest());
  if (known_mount_entry != kKnownMounts.end()) {
    // If there is a match in the list of known mounts, make sure the current
    // system context matches expectations.
    return known_mount_entry->second.Run(context);
  }
  // If there are no matches in the list of known mounts, the mount is not
  // known.
  return false;
}

std::string MountEntry::FullDescription() const {
  return base::JoinString(
      {src_.value(), dest_.value(), type_, base::JoinString(opts_, ",")}, " ");
}

}  // namespace secanomalyd
