// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "p2p/common/server_message.h"

#include <gtest/gtest.h>

namespace p2p {

namespace util {

TEST(ServerMessageTest, ValidP2PServerMessageMagicTest) {
  P2PServerMessage msg = (P2PServerMessage){.magic = 1234};
  EXPECT_FALSE(ValidP2PServerMessageMagic(msg));

  msg.magic = kP2PServerMagic;
  EXPECT_TRUE(ValidP2PServerMessageMagic(msg));
}

TEST(ServerMessageTest, ParseP2PServerMessageTypeTest) {
  P2PServerMessageType message_type = kNumP2PServerMessageTypes;

  EXPECT_FALSE(ParseP2PServerMessageType(99999, &message_type));
  EXPECT_FALSE(
      ParseP2PServerMessageType(static_cast<uint32_t>(-1), &message_type));
  EXPECT_FALSE(ParseP2PServerMessageType(
      static_cast<uint32_t>(kNumP2PServerMessageTypes), &message_type));

  EXPECT_TRUE(ParseP2PServerMessageType(
      static_cast<uint32_t>(kP2PServerNumConnections), &message_type));
  EXPECT_EQ(message_type, kP2PServerNumConnections);
}

TEST(ServerMessageTest, ParseP2PServerRequestResultTest) {
  P2PServerRequestResult req_res = kNumP2PServerRequestResults;

  EXPECT_FALSE(ParseP2PServerRequestResult(99999, &req_res));
  EXPECT_FALSE(ParseP2PServerRequestResult(static_cast<int64_t>(-1), &req_res));
  EXPECT_FALSE(ParseP2PServerRequestResult(
      static_cast<int64_t>(kNumP2PServerRequestResults), &req_res));

  EXPECT_TRUE(ParseP2PServerRequestResult(
      static_cast<int64_t>(kP2PRequestResultResponseSent), &req_res));
  EXPECT_EQ(req_res, kP2PRequestResultResponseSent);
}

}  // namespace util

}  // namespace p2p
