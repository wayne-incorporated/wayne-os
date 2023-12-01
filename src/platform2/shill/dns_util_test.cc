// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dns_util.h"

#include <iterator>

#include <gtest/gtest.h>

namespace {

bool IsValidDNSDomainName(const char* name) {
  size_t length = strlen(name);
  for (size_t i = 0; i < length; ++i) {
    if (name[i] == '.') {
      if (i == 0 || name[i - 1] == '.') {
        return false;
      }
      continue;
    }

    if (!shill::IsValidHostLabelCharacter(name[i],
                                          i == 0 || name[i - 1] == '.')) {
      return false;
    }
  }
  return true;
}

}  // namespace

namespace shill {

// IncludeNUL converts a char* to a std::string and includes the terminating
// NUL in the result.
static std::string IncludeNUL(const char* in) {
  return std::string(in, strlen(in) + 1);
}

TEST(DNSUtilTest, DNSDomainFromDot) {
  std::string out;

  EXPECT_FALSE(DNSDomainFromDot("", &out));
  EXPECT_FALSE(DNSDomainFromDot(".", &out));
  EXPECT_FALSE(DNSDomainFromDot("..", &out));
  EXPECT_FALSE(DNSDomainFromDot("foo,bar.com", &out));

  EXPECT_TRUE(DNSDomainFromDot("com", &out));
  EXPECT_EQ(out, IncludeNUL("\003com"));
  EXPECT_TRUE(DNSDomainFromDot("google.com", &out));
  EXPECT_EQ(out, IncludeNUL("\x006google\003com"));
  EXPECT_TRUE(DNSDomainFromDot("www.google.com", &out));
  EXPECT_EQ(out, IncludeNUL("\003www\006google\003com"));

  // Label is 63 chars: still valid
  EXPECT_TRUE(DNSDomainFromDot(
      "z23456789a123456789a123456789a123456789a123456789a123456789a123", &out));
  EXPECT_EQ(out,
            IncludeNUL("\077z23456789a123456789a123456789a123456789a123456789a1"
                       "23456789a123"));

  // Label is too long: invalid
  EXPECT_FALSE(DNSDomainFromDot(
      "123456789a123456789a123456789a123456789a123456789a123456789a1234",
      &out));

  // 253 characters in the name: still valid
  EXPECT_TRUE(DNSDomainFromDot(
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi."
      "abcdefghi.abcdefghi.abcdefghi.abcdefghi.abc",
      &out));
  EXPECT_EQ(
      out,
      IncludeNUL("\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi\011abcde"
                 "fghi\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi\011a"
                 "bcdefghi\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi"
                 "\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi\011abcde"
                 "fghi\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi\011a"
                 "bcdefghi\011abcdefghi\003abc"));

  // 254 characters in the name: invalid
  EXPECT_FALSE(DNSDomainFromDot(
      "123456789.123456789.123456789.123456789.123456789.123456789.123456789."
      "123456789.123456789.123456789.123456789.123456789.123456789.123456789."
      "123456789.123456789.123456789.123456789.123456789.123456789.123456789."
      "123456789.123456789.123456789.123456789.1234",
      &out));

  // Zero length labels should fail, except that one trailing dot is allowed
  // (to disable suffix search):
  EXPECT_FALSE(DNSDomainFromDot(".google.com", &out));
  EXPECT_FALSE(DNSDomainFromDot("www..google.com", &out));

  EXPECT_TRUE(DNSDomainFromDot("www.google.com.", &out));
  EXPECT_EQ(out, IncludeNUL("\003www\006google\003com"));
}

TEST(DNSUtilTest, IsValidDNSDomain) {
  const char* const bad_hostnames[] = {
      "%20%20noodles.blorg", "noo dles.blorg ",    "noo dles.blorg. ",
      "^noodles.blorg",      "noodles^.blorg",     "noo&dles.blorg",
      "noodles.blorg`",      "www.-noodles.blorg",
  };

  // TODO(palmer): In the future, when we can remove support for invalid names,
  // change the calls to from |IsValidDNSDomainName| to |IsValidDNSDomain|, and
  // remove |IsValidDNSDomainName| (defined above).

  for (size_t i = 0; i < std::size(bad_hostnames); ++i) {
    EXPECT_FALSE(IsValidDNSDomainName(bad_hostnames[i]));
  }

  const char* const good_hostnames[] = {
      "www.noodles.blorg",   "1www.noodles.blorg", "www.2noodles.blorg",
      "www.n--oodles.blorg", "www.noodl_es.blorg", "www.no-_odles.blorg",
      "www_.noodles.blorg",  "www.noodles.blorg.", "_privet._tcp.local",
  };

  for (size_t i = 0; i < std::size(good_hostnames); ++i) {
    EXPECT_TRUE(IsValidDNSDomainName(good_hostnames[i]));
  }
}

}  // namespace shill
