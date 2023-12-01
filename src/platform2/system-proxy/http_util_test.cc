// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "system-proxy/http_util.h"

#include <gtest/gtest.h>
#include <utility>

namespace {
const char kUnauthorizedResponse[] =
    "HTTP/1.1 407 Unauthorized\r\n"
    "Content-Length: 0\r\n"
    "Proxy-Authenticate: Digest realm=\"My sample realm with SP\", "
    "nonce=\"nonce-value\"\r\n"
    "Proxy-Authenticate: Basic\r\n"
    "\r\n";

}  // namespace

namespace system_proxy {

TEST(HttpUtilTest, ParseAuthChallenge) {
  auto result = ParseAuthChallenge(kUnauthorizedResponse);

  EXPECT_EQ(result.size(), 2);
  EXPECT_EQ(result[0].first, "Digest");
  EXPECT_EQ(result[0].second, "\"My sample realm with SP\"");
  EXPECT_EQ(result[1].first, "Basic");
  EXPECT_EQ(result[1].second, "");
}

}  // namespace system_proxy
