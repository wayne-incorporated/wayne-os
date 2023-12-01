// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/helpers/cups_uri_helper_utils.h"

#include <base/strings/string_number_conversions.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_util.h>

#include <cstddef>
#include <string>
#include <vector>

namespace debugd {
namespace cups_helper {

namespace {

// Evaluates true when |c| is in the reserved set specified in RFC 3986.
bool CharIsReserved(char c) {
  switch (c) {
    case ':':
    case '/':
    case '?':
    case '#':
    case '[':
    case ']':
    case '@':
    case '!':
    case '$':
    case '&':
    case '\'':
    case '(':
    case ')':
    case '*':
    case '+':
    case ',':
    case ';':
    case '=':
      return true;
  }
  return false;
}

// Evaluates true when |c| is in the unreserved set specified in RFC 3986.
bool CharIsUnreserved(char c) {
  switch (c) {
    case '-':
    case '.':
    case '_':
    case '~':
      return true;
  }
  return base::IsAsciiAlpha(c) || base::IsAsciiDigit(c);
}

// Evaluates true when |c|
// *  is in the reserved set specified by RFC 3986,
// *  is in the unreserved set specified by RFC 3986, or
// *  is a literal '%' (which is in neither preceding set).
bool CharIsAllowed(char c) {
  return CharIsReserved(c) || CharIsUnreserved(c) || c == '%';
}

// Determines whether |uri| comprises mostly alphanumeric ASCII.
bool UriIsGoodAscii(const std::string& uri) {
  int expected_hex_digits = 0;
  for (const char c : uri) {
    if (expected_hex_digits > 0) {
      // We are currently processing a percent-encoded segment "%XY."
      if (!base::IsHexDigit(c)) {
        return false;
      }
      expected_hex_digits--;
    } else if (c == '%') {
      // We are not currently processing a percent-encoded segment and
      // we see the start of a percent-encoded segment.
      expected_hex_digits = 2;
    } else if (!CharIsAllowed(c)) {
      return false;
    }
  }
  return expected_hex_digits == 0;
}

// Gets the starting index of the authority from |uri_view| - that is,
// returns the index following "://". If none is found, returns npos.
// Caller must ensure |uri_view| is already properly percent-encoded.
size_t UriAuthorityStartIndex(base::StringPiece uri_view) {
  size_t scheme_ender = uri_view.find("://");
  return scheme_ender == base::StringPiece::npos ? scheme_ender
                                                 : scheme_ender + 3;
}

// Evaluates true when |scheme_view| (including the trailing colon and 2
// slashes) equals a known printing URI scheme. Caller must ensure
// |scheme_view| is already properly percent-encoded.
bool SchemeIsForPrinting(base::StringPiece scheme_view) {
  // Enumerate known printing URIs. Values are lifted from Chrome browser's
  // Printer::GetProtocol().
  const std::vector<base::StringPiece> known_schemes = {
      "usb://",   "ipp://",    "ipps://", "http://",
      "https://", "socket://", "lpd://",  "ippusb://"};
  for (const base::StringPiece scheme : known_schemes) {
    if (base::EqualsCaseInsensitiveASCII(scheme_view, scheme)) {
      return true;
    }
  }
  return false;
}

// Evaluates true when the authority portion of a printing URI appears
// reasonable. Caller must ensure |authority_view| is already properly
// percent-encoded and does not contain the slash that begins the path.
bool AuthoritySeemsReasonable(base::StringPiece authority_view) {
  if (authority_view.empty()) {
    return false;
  }

  // My reading of RFC 3986 says to me that any non-reserved character
  // in the host can be percent-encoded. I'm going to punt on decoding
  // the variety of possible hosts and focus on the port number.
  // TODO(kdlee): figure out why nobody else in platform2 uses libcurl.
  size_t last_colon = authority_view.rfind(':');
  if (last_colon == base::StringPiece::npos) {
    // We don't see a port number - punt.
    return true;
  } else if (last_colon == authority_view.length() - 1) {
    // We see a colon but no port number - this is unreasonable.
    return false;
  }

  // There are several possibilities for other placements of the colon.
  // 1. It could be inside the user info (before host and port).
  // 2. It could be inside an IP literal (e.g. if the host is an IPv6
  //    address and no port is attached to this authority).
  // 3. It could be near the end of the authority with actual numeric
  //    values following it.
  base::StringPiece port_view = authority_view.substr(last_colon + 1);
  if (port_view.find('@') != base::StringPiece::npos) {
    // This colon is inside user info - punt.
    return true;
  } else if (base::StartsWith(authority_view, "[") &&
             base::EndsWith(authority_view, "]")) {
    // This colon is part of an IPv6 literal without a port number - punt.
    return true;
  }
  // This must be intended to be a decimal port number.
  for (const char c : port_view) {
    if (!base::IsAsciiDigit(c)) {
      return false;
    }
  }
  size_t decimal_port;
  if (!base::StringToSizeT(port_view, &decimal_port)) {
    return false;
  }
  return (0ll <= decimal_port) && (decimal_port < 65536ll);
}

}  // namespace

bool UriSeemsReasonable(const std::string& uri) {
  if (!UriIsGoodAscii(uri)) {
    return false;
  }

  base::StringPiece uri_view = uri;
  size_t authority_starter = UriAuthorityStartIndex(uri_view);
  if (authority_starter == base::StringPiece::npos ||
      authority_starter == uri_view.length()) {
    return false;
  }

  base::StringPiece scheme = uri_view.substr(0, authority_starter);
  base::StringPiece after_scheme = uri_view.substr(authority_starter);

  if (!SchemeIsForPrinting(scheme)) {
    return false;
  }

  base::StringPiece authority = after_scheme.substr(0, after_scheme.find('/'));
  if (!AuthoritySeemsReasonable(authority)) {
    return false;
  }

  return true;
}

}  // namespace cups_helper
}  // namespace debugd
