// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cups_proxy/mhd_http_request.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace cups_proxy {
namespace {

TEST(SetStatusLine, ValuesAreSaved) {
  MHDHttpRequest request;
  request.SetStatusLine("GET", "/test", "1.1");

  EXPECT_EQ(request.method(), "GET");
  EXPECT_EQ(request.url(), "/test");
  EXPECT_EQ(request.version(), "1.1");
}

TEST(AddHeader, SkipExpect100Continue) {
  MHDHttpRequest request;
  request.AddHeader("Expect", "100-continue");
  EXPECT_TRUE(request.headers().empty());
}

TEST(AddHeader, PreserveNon100Expect) {
  MHDHttpRequest request;
  request.AddHeader("Expect", "arbitrary");

  auto headers = request.headers();
  EXPECT_EQ(headers["Expect"], "arbitrary");
}

TEST(AddHeader, TrackChunkedEncoding) {
  MHDHttpRequest request;
  request.AddHeader("Transfer-Encoding", "chunked");
  request.Finalize();

  auto headers = request.headers();
  EXPECT_EQ(headers["Content-Length"], "0");
  EXPECT_EQ(headers.find("Transfer-Encoding"), headers.end());
}

TEST(AddHeader, TrackNonChunkedEncoding) {
  MHDHttpRequest request;
  request.AddHeader("Transfer-Encoding", "gzip");
  request.Finalize();

  auto headers = request.headers();
  EXPECT_EQ(headers.find("Content-Length"), headers.end());
  EXPECT_EQ(headers["Transfer-Encoding"], "gzip");
}

TEST(AddHeader, OtherHeaders) {
  MHDHttpRequest request;
  request.AddHeader("Header1", "Value1");
  request.AddHeader("Header2", "value2-test");
  request.Finalize();

  auto headers = request.headers();
  EXPECT_EQ(headers["Header1"], "Value1");
  EXPECT_EQ(headers["Header2"], "value2-test");
}

TEST(PushToBody, AddContent) {
  MHDHttpRequest request;
  request.PushToBody("line1\n");
  request.PushToBody("line2\n");

  std::string body = "line1\nline2\n";
  std::vector<unsigned char> expected(body.begin(), body.end());
  EXPECT_EQ(request.body(), expected);
}

}  // namespace
}  // namespace cups_proxy
