// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "helpers.h"

#include <string>

#include <gtest/gtest.h>

TEST(ConvertIppToHttp, InvalidUrl) {
  std::string url = "http:missing//";
  EXPECT_FALSE(ConvertIppToHttp(url));
}

TEST(ConvertIppToHttp, InvalidProtocol) {
  std::string url = "proto://ok";
  EXPECT_FALSE(ConvertIppToHttp(url));
}

TEST(ConvertIppToHttp, ConvertToHttp) {
  std::string url = "ipp://ala.ma.kota/abcd/1234";
  EXPECT_TRUE(ConvertIppToHttp(url));
  EXPECT_EQ(url, "http://ala.ma.kota:631/abcd/1234");
}

TEST(ConvertIppToHttp, ConvertToHttps) {
  std::string url = "ipps://blebleble";
  EXPECT_TRUE(ConvertIppToHttp(url));
  EXPECT_EQ(url, "https://blebleble:443");
}

TEST(ConvertIppToHttp, DoNothing) {
  std::string url = "https://ala.ma.kota:123/abcd?a=1234";
  EXPECT_TRUE(ConvertIppToHttp(url));
  EXPECT_EQ(url, "https://ala.ma.kota:123/abcd?a=1234");
}
