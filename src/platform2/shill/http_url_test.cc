// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/http_url.h"

#include <string>

#include <gtest/gtest.h>

namespace shill {

struct StringAndResult {
  explicit StringAndResult(const std::string& in_url_string)
      : url_string(in_url_string), result(false) {}

  StringAndResult(const std::string& in_url_string,
                  HttpUrl::Protocol in_protocol,
                  const std::string& in_host,
                  int in_port,
                  const std::string& in_path)
      : url_string(in_url_string),
        result(true),
        protocol(in_protocol),
        host(in_host),
        port(in_port),
        path(in_path) {}

  std::string url_string;
  bool result;
  HttpUrl::Protocol protocol;
  std::string host;
  int port;
  std::string path;
};

class HttpUrlParseTest : public testing::TestWithParam<StringAndResult> {
 protected:
  HttpUrl url_;
};

TEST_P(HttpUrlParseTest, ParseURL) {
  bool result = url_.ParseFromString(GetParam().url_string);
  EXPECT_EQ(GetParam().result, result);
  if (GetParam().result && result) {
    EXPECT_EQ(GetParam().host, url_.host());
    EXPECT_EQ(GetParam().path, url_.path());
    EXPECT_EQ(GetParam().protocol, url_.protocol());
    EXPECT_EQ(GetParam().port, url_.port());
  }
}

INSTANTIATE_TEST_SUITE_P(
    ParseFailed,
    HttpUrlParseTest,
    ::testing::Values(
        StringAndResult(""),                        // Empty string
        StringAndResult("xxx"),                     // No known prefix
        StringAndResult(" http://www.foo.com"),     // Leading garbage
        StringAndResult("http://"),                 // No hostname
        StringAndResult("http://:100"),             // Port but no hostname
        StringAndResult("http://www.foo.com:"),     // Colon but no port
        StringAndResult("http://www.foo.com:x"),    // Non-numeric port
        StringAndResult("http://foo.com:10:20")));  // Too many colons

INSTANTIATE_TEST_SUITE_P(
    ParseSucceeded,
    HttpUrlParseTest,
    ::testing::Values(StringAndResult("http://www.foo.com",
                                      HttpUrl::Protocol::kHttp,
                                      "www.foo.com",
                                      HttpUrl::kDefaultHttpPort,
                                      "/"),
                      StringAndResult("https://www.foo.com",
                                      HttpUrl::Protocol::kHttps,
                                      "www.foo.com",
                                      HttpUrl::kDefaultHttpsPort,
                                      "/"),
                      StringAndResult("https://www.foo.com:4443",
                                      HttpUrl::Protocol::kHttps,
                                      "www.foo.com",
                                      4443,
                                      "/"),
                      StringAndResult("http://www.foo.com/bar",
                                      HttpUrl::Protocol::kHttp,
                                      "www.foo.com",
                                      HttpUrl::kDefaultHttpPort,
                                      "/bar"),
                      StringAndResult("http://www.foo.com?bar",
                                      HttpUrl::Protocol::kHttp,
                                      "www.foo.com",
                                      HttpUrl::kDefaultHttpPort,
                                      "/?bar")));

}  // namespace shill
