// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_DNS_DNS_UTIL_H_
#define PATCHPANEL_DNS_DNS_UTIL_H_

#include <optional>
#include <string>

#include "base/strings/string_piece.h"
#include "brillo/brillo_export.h"

namespace patchpanel {

// DNSDomainFromDot - convert a domain string to DNS format. From DJB's
// public domain DNS library. |dotted| may include only characters a-z, A-Z,
// 0-9, -, and _.
//
//   dotted: a string in dotted form: "www.google.com"
//   out: a result in DNS form: "\x03www\x06google\x03com\x00"
BRILLO_EXPORT bool DNSDomainFromDot(const base::StringPiece& dotted,
                                    std::string* out);

// Returns true if the character is valid in a DNS hostname label, whether in
// the first position or later in the label.
//
// This function asserts a looser form of the restrictions in RFC 7719 (section
// 2; https://tools.ietf.org/html/rfc7719#section-2): hostnames can include
// characters a-z, A-Z, 0-9, -, and _, and any of those characters (except -)
// are legal in the first position. The looser rules are necessary to support
// service records (initial _), and non-compliant but attested hostnames that
// include _. These looser rules also allow Punycode and hence IDN.
//
// TODO(palmer): In the future, when we can remove support for invalid names,
// this can be a private implementation detail of |DNSDomainFromDot|, and need
// not be BRILLO_EXPORT.
BRILLO_EXPORT bool IsValidHostLabelCharacter(char c, bool is_first_char);

// Converts a domain in DNS format to a dotted string. Excludes the dot at the
// end. Assumes the standard terminating zero-length label at the end if not
// included in the input. Returns nullopt on malformed input.
BRILLO_EXPORT std::optional<std::string> DnsDomainToString(
    base::StringPiece dns_name);

}  // namespace patchpanel

#endif  // PATCHPANEL_DNS_DNS_UTIL_H_
