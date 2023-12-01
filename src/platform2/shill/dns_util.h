// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DNS_UTIL_H_
#define SHILL_DNS_UTIL_H_

#include <string>

#include <base/strings/string_piece.h>

namespace shill {
// TODO(crbug.com/751899): The DNS name validation code is adapted from
// dns_util* in Chrome:
//
// https://chromium.googlesource.com/chromium/src/+/3674d6f0ac52b4c7e3c21aa76f1cf842692ec692/net/dns/dns_util.h
//
// It would be better to include it in libchrome so that the code is
// maintained in one place.

// DNSDomainFromDot - convert a domain string to DNS format. From DJB's
// public domain DNS library.
//
//   dotted: a string in dotted form: "www.google.com"
//   out: a result in DNS form: "\x03www\x06google\x03com\x00"
bool DNSDomainFromDot(const base::StringPiece& dotted, std::string* out);

// Checks that a hostname is valid. Simple wrapper around DNSDomainFromDot.
bool IsValidDNSDomain(const base::StringPiece& dotted);

// Returns true if the character is valid in a DNS hostname label, whether in
// the first position or later in the label.
//
// This function asserts a looser form of the restrictions in RFC 7719 (section
// 2; https://tools.ietf.org/html/rfc7719#section-2): hostnames can include
// characters a-z, A-Z, 0-9, -, and _, and any of those characters (except -)
// are legal in the first position. The looser rules are necessary to support
// service records (initial _), and non-compliant but attested hostnames that
// include _. These looser rules also allow Punycode and hence IDN.
bool IsValidHostLabelCharacter(char c, bool is_first_char);

}  // namespace shill

#endif  // SHILL_DNS_UTIL_H_
