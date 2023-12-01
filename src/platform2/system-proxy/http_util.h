// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef SYSTEM_PROXY_HTTP_UTIL_H_
#define SYSTEM_PROXY_HTTP_UTIL_H_

#include <string>
#include <utility>
#include <vector>

#include <base/strings/string_util.h>

// TODO(acostinas,crbug.com/1094205): Add fuzzer tests.
namespace system_proxy {

// List of scheme and realm pairs. The |first| item in each entry represents the
// HTTP authentication scheme and |second| item represents the realm of the
// server where the challenge is originating from.
using SchemeRealmPairList = std::vector<std::pair<std::string, std::string>>;

// Verifies if the http headers are ending with an http empty line, meaning a
// line that contains only CRLF or LF preceded by a line ending with CRLF.
bool IsEndingWithHttpEmptyLine(const base::StringPiece& http_header_line);

// Analyses |input| and attempts to find a complete HTTP request (request line,
// headers and end of message). Returns false if it is not found or only a
// partial HTTP request is in |input|. Returns true if an HTTP request is found,
// and puts the HTTP request into *|out_http_request|, including the end tag
// (two newlines). Any remaining data is put into *|out_remaining_data|.
bool ExtractHTTPRequest(const std::vector<char>& input,
                        std::vector<char>* out_http_request,
                        std::vector<char>* out_remaining_data);

// Parses the first line of the http CONNECT request and extracts the URI
// authority, defined in RFC3986, section 3.2, as the host name and port number
// separated by a colon. The destination URI is specified in the request line
// (RFC2817, section 5.2):
//      CONNECT server.example.com:80 HTTP/1.1
// If the first line in |raw_request| (the Request-Line) is a correctly formed
// CONNECT request, it will return the destination URI as host:port, otherwise
// it will return an empty string.
std::string GetUriAuthorityFromHttpHeader(
    const base::StringPiece& http_request);

// Parses the HTTP server reply and extracts the supported authentication scheme
// and realm.
SchemeRealmPairList ParseAuthChallenge(const base::StringPiece& http_request);
}  // namespace system_proxy

#endif  // SYSTEM_PROXY_HTTP_UTIL_H_
