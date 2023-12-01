// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/quote.h"

#include <iomanip>

#include "base/strings/string_piece.h"
#include "base/strings/string_util.h"

namespace cros_disks {

static const char kRedacted[] = "***";

std::ostream& operator<<(std::ostream& out, Quoter<const char*> quoter) {
  const char* const s = quoter.ref;
  if (!s)
    return out << "(null)";

  if (!*s || !quoter.redacted)
    return out << std::quoted(s, '\'');

  return out << kRedacted;
}

std::ostream& operator<<(std::ostream& out, Quoter<std::string> quoter) {
  const std::string& s = quoter.ref;

  if (s.empty() || !quoter.redacted)
    return out << std::quoted(s, '\'');

  DCHECK(!s.empty());
  if (s.front() == '/')
    return out << redact(base::FilePath(s), quoter.redacted);

  for (const base::StringPiece prefix :
       {"sftp://", "fusebox://", "smbfs://", "drivefs://"}) {
    if (base::StartsWith(s, prefix))
      return out << '\'' << prefix << kRedacted << '\'';
  }

  return out << kRedacted;
}

std::ostream& operator<<(std::ostream& out, Quoter<base::FilePath> quoter) {
  const base::FilePath& p = quoter.ref;
  const std::string& s = p.value();

  if (s.empty() || !quoter.redacted)
    return out << std::quoted(s, '\'');

  for (const base::StringPiece prefix :
       {"/media/archive/", "/media/removable/", "/media/fuse/crostini_",
        "/media/fuse/smbfs-", "/media/fuse/drivefs-", "/media/fuse/fusebox/",
        "/home/chronos/", "/run/arc/sdcard/"}) {
    if (base::StartsWith(s, prefix))
      return out << '\'' << prefix << kRedacted << p.Extension() << '\'';
  }

  return out << std::quoted(s, '\'');
}

}  // namespace cros_disks
