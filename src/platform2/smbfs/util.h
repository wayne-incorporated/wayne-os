// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBFS_UTIL_H_
#define SMBFS_UTIL_H_

#include <string>
#include <vector>

#include <stdint.h>

namespace smbfs {

// Returns a string representation of the open() flags combined to produce
// |flags| (eg. "O_RDWR|O_DIRECT|O_TRUNC").
std::string OpenFlagsToString(int flags);

// Returns a string representation of the FUSE_SET_ATTR_* flags combined to
// produce |flags|.
std::string ToSetFlagsToString(int flags);

// Returns the string representation of |address|. |address| is expected to be
// the four bytes of an IPv4 address in network byte order. If |address| is not
// a valid IPv4 address, return the empty string.
// TODO(crbug.com/1051291): Support IPv6.
std::string IpAddressToString(const std::vector<uint8_t>& address);

}  // namespace smbfs

#endif  // SMBFS_UTIL_H_
