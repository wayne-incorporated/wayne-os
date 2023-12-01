// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dns_util.h"

#include <errno.h>
#include <limits.h>
#include <netinet/in.h>

#include <cstring>

#include <base/metrics/field_trial.h>
#include <base/metrics/histogram_macros.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>

namespace {

// RFC 1035, section 2.3.4: labels 63 octets or less.
// Section 3.1: Each label is represented as a one octet length field followed
// by that number of octets.
const int kMaxLabelLength = 63;

// RFC 1035, section 3.1: To simplify implementations, the total length of
// a domain name (i.e., label octets and label length octets) is restricted
// to 255 octets or less.
const int kMaxNameLength = 255;

}  // namespace

namespace shill {

// Based on DJB's public domain code.
bool DNSDomainFromDot(const base::StringPiece& dotted, std::string* out) {
  const char* buf = dotted.data();
  size_t n = dotted.size();
  char label[kMaxLabelLength];
  size_t labellen = 0; /* <= sizeof label */
  char name[kMaxNameLength];
  size_t namelen = 0; /* <= sizeof name */
  char ch;

  for (;;) {
    if (!n)
      break;
    ch = *buf++;
    --n;
    if (ch == '.') {
      // Don't allow empty labels per http://crbug.com/456391.
      if (!labellen)
        return false;
      if (namelen + labellen + 1 > sizeof name)
        return false;
      name[namelen++] = static_cast<char>(labellen);
      memcpy(name + namelen, label, labellen);
      namelen += labellen;
      labellen = 0;
      continue;
    }
    if (labellen >= sizeof label)
      return false;
    if (!IsValidHostLabelCharacter(ch, labellen == 0)) {
      return false;
    }
    label[labellen++] = ch;
  }

  // Allow empty label at end of name to disable suffix search.
  if (labellen) {
    if (namelen + labellen + 1 > sizeof name)
      return false;
    name[namelen++] = static_cast<char>(labellen);
    memcpy(name + namelen, label, labellen);
    namelen += labellen;
    labellen = 0;
  }

  if (namelen + 1 > sizeof name)
    return false;
  if (namelen == 0)  // Empty names e.g. "", "." are not valid.
    return false;
  name[namelen++] = 0;  // This is the root label (of length 0).

  *out = std::string(name, namelen);
  return true;
}

bool IsValidDNSDomain(const base::StringPiece& dotted) {
  std::string dns_formatted;
  return DNSDomainFromDot(dotted, &dns_formatted);
}

bool IsValidHostLabelCharacter(char c, bool is_first_char) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
         (c >= '0' && c <= '9') || (!is_first_char && c == '-') || c == '_';
}

}  // namespace shill
