// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/tools/battery_saver/proto_util.h"

#include <google/protobuf/util/message_differencer.h>
#include <gtest/gtest.h>
#include <power_manager/proto_bindings/battery_saver.pb.h>

namespace power_manager {
namespace {

TEST(ProtoUtil, SerializeDeserialize) {
  // Construct an example proto.
  BatterySaverModeState original;
  original.set_enabled(true);
  original.set_cause(BatterySaverModeState_Cause_CAUSE_USER_DISABLED);

  // Serialize it, and deserialize it again.
  std::vector<uint8_t> bytes = SerializeProto(original);
  EXPECT_GT(bytes.size(), 0);
  std::optional<BatterySaverModeState> deserialized =
      DeserializeProto<BatterySaverModeState>(bytes);
  ASSERT_TRUE(deserialized.has_value());

  // Ensure the protos match.
  EXPECT_EQ(original.enabled(), deserialized->enabled());
  EXPECT_EQ(original.cause(), deserialized->cause());
}

TEST(ProtoUtil, DeserializeBadBytes) {
  // << 0x11 0x01 >> is a bad protobuf, because it is truncated:
  //
  //   * 0x11 ==> A string with tag "1"
  //   * 0x01 ==> ... that has a length of 0x01.
  //   * <eof>
  //
  // We expect `std::nullopt` to be returned.
  EXPECT_EQ(std::nullopt,
            DeserializeProto<BatterySaverModeState>({0x11, 0x01}));
}

}  // namespace
}  // namespace power_manager
