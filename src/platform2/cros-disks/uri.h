// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_URI_H_
#define CROS_DISKS_URI_H_

#include <string>

#include <base/strings/string_piece.h>

namespace cros_disks {

// Wrapper for string representing URI. By no mean it's a complete
// implementation of what should be in such class, just to group some
// related utilities.
class Uri {
 public:
  // Creates an invalid Uri.
  Uri() = default;

  // Creates a Uri with the given scheme and path.
  Uri(base::StringPiece scheme, base::StringPiece path);

  bool operator==(const Uri& other) const { return value() == other.value(); }

  // Gets the value of this Uri as "<scheme>://<path>", or an empty string if
  // this Uri is not valid.
  std::string value() const;

  const std::string& scheme() const { return scheme_; }
  const std::string& path() const { return path_; }

  // Returns true if the scheme is not empty.
  bool valid() const { return !scheme_.empty(); }

  // Returns true if the given string is URI, i.e. <scheme>://[something].
  // It checks only the scheme part and doesn't verify validity of the path.
  static bool IsUri(base::StringPiece s) { return Parse(s).valid(); }

  // Parses the given string s as a URI. If s doesn't have a valid scheme, then
  // a Uri with an empty scheme, ie an invalid Uri, is returned.
  static Uri Parse(base::StringPiece s);

 private:
  std::string scheme_;
  std::string path_;
};

}  // namespace cros_disks

#endif  // CROS_DISKS_URI_H_
