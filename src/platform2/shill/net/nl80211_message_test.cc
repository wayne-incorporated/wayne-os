// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/net/nl80211_message.h"

#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "shill/net/byte_string.h"

namespace shill {
namespace {

// wlan0 (phy #0): auth c0:3f:0e:77:e8:7f -> 48:5d:60:77:2d:cf status: 0:
// Successful [frame: b0 00 3a 01 48 5d 60 77 2d cf c0 3f 0e 77 e8 7f c0
// 3f 0e 77 e8 7f 30 07 00 00 02 00 00 00]
const unsigned char kAuthenticateFrame[] = {
    0xb0, 0x00, 0x3a, 0x01, 0x48, 0x5d, 0x60, 0x77, 0x2d, 0xcf,
    0xc0, 0x3f, 0x0e, 0x77, 0xe8, 0x7f, 0xc0, 0x3f, 0x0e, 0x77,
    0xe8, 0x7f, 0x30, 0x07, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
};

// wlan0 (phy #0): deauth c0:3f:0e:77:e8:7f -> ff:ff:ff:ff:ff:ff reason 2:
// Previous authentication no longer valid [frame: c0 00 00 00 ff ff ff ff
// ff ff c0 3f 0e 77 e8 7f c0 3f 0e 77 e8 7f c0 0e 02 00]
const unsigned char kDeauthenticateFrame[] = {
    0xc0, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xc0, 0x3f, 0x0e, 0x77, 0xe8, 0x7f, 0xc0, 0x3f,
    0x0e, 0x77, 0xe8, 0x7f, 0xc0, 0x0e, 0x02, 0x00,
};

TEST(Nl80211FrameTest, EmptyFrameToString) {
  Nl80211Frame frame(ByteString{});
  EXPECT_EQ(frame.ToString(), "[no frame]");
  EXPECT_EQ(frame.frame_type(), Nl80211Frame::kIllegalFrameType);
}

TEST(Nl80211FrameTest, ToStringWithStatus) {
  Nl80211Frame frame(
      ByteString(kAuthenticateFrame, sizeof(kAuthenticateFrame)));
  std::string expected_output =
      "48:5d:60:77:2d:cf -> c0:3f:0e:77:e8:7f; Auth status: 0: Successful "
      "[frame: b0, 00, 3a, 01, 48, 5d, 60, 77, 2d, cf, c0, 3f, 0e, 77, e8, 7f, "
      "c0, 3f, 0e, 77, e8, 7f, 30, 07, 00, 00, 02, 00, 00, 00, ]";
  EXPECT_EQ(frame.ToString(), expected_output);
}

TEST(Nl80211FrameTest, ToStringWithReason) {
  Nl80211Frame frame(
      ByteString(kDeauthenticateFrame, sizeof(kDeauthenticateFrame)));
  std::string expected_output =
      "ff:ff:ff:ff:ff:ff -> c0:3f:0e:77:e8:7f; Deauth reason 2: Previous "
      "authentication no longer valid [frame: c0, 00, 00, 00, ff, ff, ff, ff, "
      "ff, ff, c0, 3f, 0e, 77, e8, 7f, c0, 3f, 0e, 77, e8, 7f, c0, 0e, 02, 00, "
      "]";
  EXPECT_EQ(frame.ToString(), expected_output);
  EXPECT_EQ(frame.frame_type(), Nl80211Frame::kDeauthFrameType);
  EXPECT_EQ(frame.reason(), 2);
}

}  // namespace
}  // namespace shill
