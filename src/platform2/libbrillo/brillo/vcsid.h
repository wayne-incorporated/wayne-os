// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// This file exposes two constexpr values |kVCSID| and |kShortVCSID|.
// These are translations of the build system's |VCSID| macro into pure C++
// constants.
//
// The bellow |kVCSID| and |kShortVCSID| definitions are in an anonymous
// namesace inside a header file because |VCSID| is set as a preprocessor macro
// by the build system for a particular package. So, the |VCSID| seen by a
// libbrillo source file will be different to that seen by a source file
// in the biod package, at compile time.
//
// To avoid ODR violations (and odd behavior) these constants should not be
// used in any header files that could be potentially shared across
// packages. This is because redefinitions of identical inline [header]
// functions is allowed, but an inline function that uses this constant will
// have a different definitions across packages. In practice, the
// compiler/linker silently chooses one of the definitions, which may not be
// the one you expected.

#ifndef LIBBRILLO_BRILLO_VCSID_H_
#define LIBBRILLO_BRILLO_VCSID_H_

#include <cctype>

#include <openssl/sha.h>

#include <string_view>
#include <optional>

#include <base/logging.h>

namespace brillo {

namespace vcsid_internal {

// Checks if |str| could be a SHA1 hash encoded as a hexadecimal string.
constexpr bool IsSHA1HexString(const std::string_view& str) {
  if (str.length() != (2 * SHA_DIGEST_LENGTH))
    return false;

  return str.find_first_not_of("0123456789ABCDEFabcdef") ==
         std::string_view::npos;
}

// Checks if |vcsid| matches our expected VCSID pattern.
constexpr bool IsValidVCSID(const std::string_view& vcsid) {
  const std::size_t delim = vcsid.find_last_of('-');

  // Check that there is a '-' delimiter.
  if (delim == std::string_view::npos)
    return false;

  return IsSHA1HexString(vcsid.substr(delim + 1));
}

// Parameter |vcsid| is assumed to be IsValidVCSID(vcsid).
constexpr std::string_view ShortenVCSID(const std::string_view& vcsid) {
  // If IsValidVCSID(vcsid), vcsid is is guaranteed to contain a '-' and
  // the trailing part is larger than 10 characters.
  return vcsid.substr(0, vcsid.find_last_of('-') + 1 + 10);
}

}  // namespace vcsid_internal

namespace {  // NOLINT(build/namespaces)

// |kVCSID| is the full VCSID reported from the package build system as a
// string. This requires "CROS_WORKON_USE_VCSID=1" to be set in the pkg ebuild.
// Return nullopt if VCSID was not set (CROS_WORKON_USE_VCSID not enabled).
//
// The string is of the format <GENTOO_PVR>-<VCS_REV_ID>, where
// GENTOO_PVR could be 9999 or <sw_ver>-<pkg_rev>.
//
// Examples:
// * "9999-67ec4c03828a50c2b8cacba45c0cf5f9b4f2ff34"
// * "0.0.1-r2004-67ec4c03828a50c2b8cacba45c0cf5f9b4f2ff34"
constexpr std::optional<std::string_view> kVCSID =
#ifdef VCSID
    std::string_view(VCSID);
#else
    std::nullopt;
#endif

// |kShortVCSID| is |kVCSID|, but with a shorter git hash.
// This is useful when logging the VCSID, since the full git SHA1 would
// be automatically shortened to an unusable small length by the feedback report
// log sanitizer. We pre-shorten the hash to a usable 10 characters so that
// the sanitizer ignores it.
// Return nullopt if |kVCSID| is nullopt.
//
// Example usage:
//   #include <base/logging.h>
//   LOG(INFO) << "Version ID: " << brillo::kShortVCSID.value_or("VCSID UNSET");
static_assert(!kVCSID || vcsid_internal::IsValidVCSID(*kVCSID),
              "VCSID doesn't match the expected format.");
constexpr std::optional<std::string_view> kShortVCSID =
    kVCSID
        ? std::optional<std::string_view>(vcsid_internal::ShortenVCSID(*kVCSID))
        : std::optional<std::string_view>(std::nullopt);

}  // namespace

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_VCSID_H_
