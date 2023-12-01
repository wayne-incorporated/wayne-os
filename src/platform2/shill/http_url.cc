// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/http_url.h"

#include <string>
#include <vector>

#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>

namespace shill {

namespace {

constexpr char kDelimiters[] = " /#?";
constexpr char kPortSeparator = ':';
constexpr char kPrefixHttp[] = "http://";
constexpr char kPrefixHttps[] = "https://";

}  //  namespace

const int HttpUrl::kDefaultHttpPort = 80;
const int HttpUrl::kDefaultHttpsPort = 443;

HttpUrl::HttpUrl() : port_(kDefaultHttpPort), protocol_(Protocol::kHttp) {}

HttpUrl::~HttpUrl() = default;

bool HttpUrl::ParseFromString(const std::string& url_string) {
  Protocol protocol = Protocol::kUnknown;
  size_t host_start = 0;
  int port = 0;
  const std::string http_url_prefix(kPrefixHttp);
  const std::string https_url_prefix(kPrefixHttps);
  if (url_string.substr(0, http_url_prefix.length()) == http_url_prefix) {
    host_start = http_url_prefix.length();
    port = kDefaultHttpPort;
    protocol = Protocol::kHttp;
  } else if (url_string.substr(0, https_url_prefix.length()) ==
             https_url_prefix) {
    host_start = https_url_prefix.length();
    port = kDefaultHttpsPort;
    protocol = Protocol::kHttps;
  } else {
    return false;
  }

  size_t host_end = url_string.find_first_of(kDelimiters, host_start);
  if (host_end == std::string::npos) {
    host_end = url_string.length();
  }
  const auto host_parts = base::SplitString(
      url_string.substr(host_start, host_end - host_start),
      std::string{kPortSeparator}, base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);

  if (host_parts.empty() || host_parts[0].empty() || host_parts.size() > 2) {
    return false;
  }

  if (host_parts.size() == 2) {
    if (!base::StringToInt(host_parts[1], &port)) {
      return false;
    }
  }

  protocol_ = protocol;
  host_ = host_parts[0];
  port_ = port;
  path_ = url_string.substr(host_end);
  if (path_.empty() || path_[0] != '/') {
    path_ = "/" + path_;
  }

  return true;
}

}  // namespace shill
