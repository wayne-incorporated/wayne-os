// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "system-proxy/http_util.h"

#include <array>
#include <string_view>

#include <curl/curl.h>

#include <base/strings/stringprintf.h>
#include <base/strings/string_split.h>
#include <base/strings/string_tokenizer.h>
#include <base/strings/string_util.h>

namespace {
// The elements in this array are used to identify the end of a HTTP header
// which should be an empty line. Note: all HTTP header lines end with CRLF.
// RFC7230, section 3.5 allow LF (without CR) as a valid end of header. HTTP
// connect requests don't have a body so end of header is end of request.
static const std::array<std::string, 2> kValidHttpHeaderEnd = {"\r\n\n",
                                                               "\r\n\r\n"};
constexpr char kConnectMethod[] = "CONNECT";
constexpr char kProxyAuthenticate[] = "Proxy-Authenticate:";
const std::string_view kRealm = "realm=";
}  // namespace

namespace system_proxy {

bool IsEndingWithHttpEmptyLine(const base::StringPiece& http_header_line) {
  for (const auto& header_end : kValidHttpHeaderEnd) {
    if (http_header_line.size() > header_end.size() &&
        std::memcmp(header_end.data(),
                    http_header_line.data() + http_header_line.size() -
                        header_end.size(),
                    header_end.size()) == 0) {
      return true;
    }
  }
  return false;
}

bool ExtractHTTPRequest(const std::vector<char>& input,
                        std::vector<char>* out_http_request,
                        std::vector<char>* out_remaining_data) {
  for (const auto& header_end : kValidHttpHeaderEnd) {
    auto it = std::search(input.begin(), input.end(), header_end.c_str(),
                          header_end.c_str() + header_end.length());
    if (it == input.end())
      continue;
    it += header_end.length();
    *out_http_request = {input.begin(), it};
    *out_remaining_data = {it, input.end()};
    return true;
  }
  return false;
}

std::string GetUriAuthorityFromHttpHeader(
    const base::StringPiece& http_request) {
  // Request-Line ends with CRLF (RFC2616, section 5.1).
  size_t i = http_request.find("\r\n");
  if (i == base::StringPiece::npos)
    return std::string();
  // Elements are delimited by non-breaking space (SP).
  auto pieces =
      base::SplitString(http_request.substr(0, i), " ", base::TRIM_WHITESPACE,
                        base::SPLIT_WANT_NONEMPTY);
  // Request-Line has the format: Method SP Request-URI SP HTTP-Version CRLF.
  if (pieces.size() < 3)
    return std::string();
  if (pieces[0] != kConnectMethod)
    return std::string();

  return pieces[1];
}

SchemeRealmPairList ParseAuthChallenge(const base::StringPiece& http_request) {
  SchemeRealmPairList scheme_realm_pairs;
  std::string scheme;
  std::string realm;
  std::vector<std::string> header_lines = base::SplitString(
      http_request, "\r\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  for (const auto& line : header_lines) {
    base::StringTokenizer tok_challenge(line, " ");
    tok_challenge.GetNext();
    if (tok_challenge.token() != kProxyAuthenticate) {
      continue;
    }

    tok_challenge.GetNext();
    scheme = tok_challenge.token();
    realm = std::string();
    // Depending on the challenge scheme, the challenge can contain a
    // comma-separated list of authenticatio parameters. See RFC7235,
    // section 4.3.
    base::StringTokenizer tok_realm(tok_challenge.token_end(), line.end(), ",");
    tok_realm.set_quote_chars("\"");
    while (tok_realm.GetNext()) {
      int pos = tok_realm.token().find(kRealm);
      if (pos != std::string::npos) {
        realm = tok_realm.token().substr(pos + kRealm.size());
      }
    }
    scheme_realm_pairs.push_back(std::make_pair(scheme, realm));
  }

  return scheme_realm_pairs;
}
}  // namespace system_proxy
