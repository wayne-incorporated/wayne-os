// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "debugd/src/helpers/cups_uri_helper_utils.h"

namespace debugd {
namespace cups_helper {
namespace {

static const char* known_schemes[] = {"usb://",  "ipp://",   "ipps://",
                                      "http://", "https://", "socket://",
                                      "lpd://",  "ippusb://"};

// We reject empty and over-short URIs.
TEST(CupsUriHelperTest, CatchShortUri) {
  // This URI is trivially bad.
  EXPECT_FALSE(UriSeemsReasonable(""));

  // Our URIs must have an authority - it's too short otherwise.
  for (const char* sch : known_schemes) {
    EXPECT_FALSE(UriSeemsReasonable(sch));
  }
}

// We reject strings obviously dissimilar to HTTP URIs.
TEST(CupsUriHelperTest, CatchGarbageUri) {
  // This is straight nonsense.
  EXPECT_FALSE(UriSeemsReasonable("aoeu"));
  // We expect 2 slashes preceding the authority.
  EXPECT_FALSE(UriSeemsReasonable("ipps:/i-accidentally-a-slash"));
}

// URIs must not contain literal spaces.
TEST(CupsUriHelperTest, DontAllowSpaces) {
  EXPECT_FALSE(UriSeemsReasonable("ipp:// 127.0.0.1:9001/hello-there"));
  EXPECT_FALSE(UriSeemsReasonable("ipp://127. 0.0.1:9001/hello-there"));
  EXPECT_FALSE(UriSeemsReasonable("ipp://127.0.0.1:90 01/hello-there"));
  EXPECT_FALSE(UriSeemsReasonable("ipp://127.0.0.1:9001 /hello-there"));
  EXPECT_FALSE(UriSeemsReasonable("ipp://127.0.0.1:9001/ hello-there"));
  EXPECT_FALSE(UriSeemsReasonable("ipp://127.0.0.1:9001/hello- there"));
}

// URIs must not contain characters outside the printable ASCII range.
TEST(CupsUriHelperTest, DontAllowUnprintableOctets) {
  EXPECT_FALSE(
      UriSeemsReasonable("ipp://\x7F"
                         "127.0.0.1:9001/hello-there"));
  EXPECT_FALSE(UriSeemsReasonable("ipp://127.0.0.1:9001\x7F/hello-there"));
  EXPECT_FALSE(UriSeemsReasonable("ipp://127.0.0.1:7001/hello-there\x7F"));
}

// We pass URIs not violating the above conditions.
TEST(CupsUriHelperTest, OkayUri) {
  for (const char* uri : known_schemes) {
    std::string new_uri = uri;
    // Tack on any old hostname (and then some) to make a valid URI.
    new_uri.append("1.2.3.4:9001/ipp/print");
    EXPECT_TRUE(UriSeemsReasonable(new_uri));
  }
}

TEST(CupsUriHelperTest, PercentedUris) {
  std::string uri_with_space("lpd://127.0.0.1/PRINTER%20NAME");
  EXPECT_TRUE(UriSeemsReasonable(uri_with_space));

  // We allow valid percent encodings anywhere after the scheme.
  std::string lots_of_percents("lpd://%20%FF%00%20%2E/PRINTER%20NAME");
  EXPECT_TRUE(UriSeemsReasonable(lots_of_percents));
}

TEST(CupsUriHelperTest, InvalidPercentedUris) {
  std::string incomplete("lpd://127.0.0.1/PRINTER%2");
  EXPECT_FALSE(UriSeemsReasonable(incomplete));

  std::string bad_hex("lpd://127.0.0.1/PRINTER%ZZ%ZZ");
  EXPECT_FALSE(UriSeemsReasonable(bad_hex));
}

TEST(CupsUriHelperTest, PortNumbers) {
  // URIs might not refer to a port number.
  EXPECT_TRUE(UriSeemsReasonable("ipp://[2001:4860:4860::8888]"));
  EXPECT_TRUE(UriSeemsReasonable("ipp://localhost"));
  EXPECT_TRUE(UriSeemsReasonable("ipp://127.0.0.1"));

  // If there is a port number, it must be in range.
  EXPECT_TRUE(UriSeemsReasonable("ipp://[2001:4860:4860::8888]:65535"));
  EXPECT_FALSE(UriSeemsReasonable("ipp://[2001:4860:4860::8888]:65536"));
  EXPECT_TRUE(UriSeemsReasonable("ipp://localhost:65535"));
  EXPECT_FALSE(UriSeemsReasonable("ipp://localhost:65536"));
  EXPECT_TRUE(UriSeemsReasonable("ipp://127.0.0.1:65535"));
  EXPECT_FALSE(UriSeemsReasonable("ipp://127.0.0.1:65536"));
}

TEST(CupsUriHelperTest, PortNumbersAndPaths) {
  // Port number range checks should work with trailing characters beyond
  // the port number.
  EXPECT_TRUE(UriSeemsReasonable("ipp://[2001:4860:4860::8888]:65535/"));
  EXPECT_TRUE(
      UriSeemsReasonable("ipp://[2001:4860:4860::8888]:65535/blah%20blah"));
  EXPECT_FALSE(UriSeemsReasonable("ipp://[2001:4860:4860::8888]:65536/"));
  EXPECT_FALSE(
      UriSeemsReasonable("ipp://[2001:4860:4860::8888]:65536/blah%20blah"));
  EXPECT_TRUE(UriSeemsReasonable("ipp://localhost:65535/"));
  EXPECT_TRUE(UriSeemsReasonable("ipp://localhost:65535/blah%20blah"));
  EXPECT_FALSE(UriSeemsReasonable("ipp://localhost:65536/"));
  EXPECT_FALSE(UriSeemsReasonable("ipp://localhost:65536/blah%20blah"));
  EXPECT_TRUE(UriSeemsReasonable("ipp://127.0.0.1:65535/"));
  EXPECT_TRUE(UriSeemsReasonable("ipp://127.0.0.1:65535/blah%20blah"));
  EXPECT_FALSE(UriSeemsReasonable("ipp://127.0.0.1:65536/"));
  EXPECT_FALSE(UriSeemsReasonable("ipp://127.0.0.1:65536/blah%20blah"));
}

}  // namespace
}  // namespace cups_helper
}  // namespace debugd
