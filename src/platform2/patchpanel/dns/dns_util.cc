// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/dns/dns_util.h"

#include <errno.h>
#include <limits.h>

#include <optional>
#include <string>

#include "patchpanel/dns/dns_protocol.h"

namespace {

// RFC 1035, section 2.3.4: labels 63 octets or less.
// Section 3.1: Each label is represented as a one octet length field followed
// by that number of octets.
const int kMaxLabelLength = 63;

}  // namespace

#if defined(OS_POSIX)
#include <netinet/in.h>
#if !defined(OS_NACL)
#include <net/if.h>
#if !defined(OS_ANDROID)
#include <ifaddrs.h>
#endif  // !defined(OS_ANDROID)
#endif  // !defined(OS_NACL)
#endif  // defined(OS_POSIX)

#if defined(OS_ANDROID)
#include "net/android/network_library.h"
#endif

namespace patchpanel {
namespace {

// Based on DJB's public domain code.
bool DNSDomainFromDot(const base::StringPiece& dotted,
                      bool is_unrestricted,
                      std::string* out) {
  const char* buf = dotted.data();
  size_t n = dotted.size();
  char label[kMaxLabelLength];
  size_t labellen = 0; /* <= sizeof label */
  char name[dns_protocol::kMaxNameLength];
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
    if (!is_unrestricted && !IsValidHostLabelCharacter(ch, labellen == 0)) {
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

}  // namespace

bool DNSDomainFromDot(const base::StringPiece& dotted, std::string* out) {
  return DNSDomainFromDot(dotted, false /* is_unrestricted */, out);
}

bool IsValidHostLabelCharacter(char c, bool is_first_char) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
         (c >= '0' && c <= '9') || (!is_first_char && c == '-') || c == '_';
}

std::optional<std::string> DnsDomainToString(base::StringPiece domain) {
  std::string ret;

  for (unsigned i = 0; i < domain.size() && domain[i];
       i += static_cast<unsigned>(domain[i]) + 1) {
#if CHAR_MIN < 0
    if (domain[i] < 0)
      return std::nullopt;
#endif
    if (domain[i] > kMaxLabelLength)
      return std::nullopt;

    if (i)
      ret += ".";

    if (static_cast<unsigned>(domain[i]) + i + 1 > domain.size())
      return std::nullopt;

    ret.append(domain.data() + i + 1, static_cast<size_t>(domain[i]));
  }
  return ret;
}

}  // namespace patchpanel
