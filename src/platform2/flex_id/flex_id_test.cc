// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "flex_id/flex_id.h"

#include <optional>

#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

namespace flex_id {

namespace {

constexpr char kGoodFlexId[] = "good_example_flex_id";
constexpr char kClientId[] = "reven-client_id";
constexpr char kLegacyClientId[] = "CloudReady-aa:aa:aa:11:22:33";
constexpr char kUuid[] = "fc71ace7-5fbb-4108-a2f5-b48a98635aeb";
constexpr char kGoodSerial[] = "good_example_serial";
constexpr char kBadSerial[] = "to be filled by o.e.m.";
constexpr char kShortSerial[] = "a";
constexpr char kRepeatedSerial[] = "aaaaaa";
constexpr char kPriorityInterfaceName[] = "eth0";
constexpr char kGoodInterfaceName[] = "wlan1";
constexpr char kBadInterfaceName[] = "arc_1";
constexpr char kGoodMacAddress[] = "aa:bb:cc:11:22:33";
constexpr char kGoodMacAddress2[] = "dd:ee:ff:44:55:66";
constexpr char kBadMacAddress[] = "00:00:00:00:00:00";
constexpr char kPciModAlias[] = "pci:0000";
constexpr char kUsbModAlias[] = "usb:0000";

}  // namespace

class FlexIdTest : public ::testing::Test {
 protected:
  void SetUp() override {
    CHECK(test_dir_.CreateUniqueTempDir());
    test_path_ = test_dir_.GetPath();
    flex_id_generator_ = flex_id::FlexIdGenerator(test_path_);
  }

  void CreateSerial(const std::string& serial) {
    base::FilePath serial_path =
        test_path_.Append("sys/devices/virtual/dmi/id");
    CHECK(base::CreateDirectory(serial_path));
    CHECK(base::WriteFile(serial_path.Append("product_serial"), serial));
  }

  void CreateInterface(const std::string& name,
                       const std::string& address,
                       const std::string& modalias) {
    base::FilePath interface_path =
        test_path_.Append("sys/class/net").Append(name);
    CHECK(base::CreateDirectory(interface_path.Append("device")));
    CHECK(base::WriteFile(interface_path.Append("address"), address));
    CHECK(base::WriteFile(interface_path.Append("device").Append("modalias"),
                          modalias));
  }

  void CreateClientId() {
    base::FilePath client_id_path = test_path_.Append("var/lib/client_id");
    CHECK(base::CreateDirectory(client_id_path));
    CHECK(base::WriteFile(client_id_path.Append("client_id"), kClientId));
  }

  void CreateLegacy() {
    base::FilePath legacy_path =
        test_path_.Append("mnt/stateful_partition/cloudready");
    CHECK(base::CreateDirectory(legacy_path));
    CHECK(base::WriteFile(legacy_path.Append("client_id"), kLegacyClientId));
  }

  void CreateUuid() {
    base::FilePath uuid_path = test_path_.Append("proc/sys/kernel/random");
    CHECK(base::CreateDirectory(uuid_path));
    CHECK(base::WriteFile(uuid_path.Append("uuid"), kUuid));
  }

  void CreateFlexId(const std::string& flex_id) {
    base::FilePath flex_id_path = test_path_.Append("var/lib/flex_id");
    CHECK(base::CreateDirectory(flex_id_path));
    CHECK(base::WriteFile(flex_id_path.Append("flex_id"), flex_id));
  }

  void DeleteFlexId() {
    base::FilePath flex_id_path = test_path_.Append("var/lib/flex_id/flex_id");
    CHECK(base::DeleteFile(flex_id_path));
  }

  std::optional<flex_id::FlexIdGenerator> flex_id_generator_;
  base::ScopedTempDir test_dir_;
  base::FilePath test_path_;
};

TEST_F(FlexIdTest, ClientId) {
  EXPECT_FALSE(flex_id_generator_->TryClientId());

  CreateClientId();
  EXPECT_EQ(flex_id_generator_->TryClientId(), kClientId);
}

TEST_F(FlexIdTest, LegacyClientId) {
  EXPECT_FALSE(flex_id_generator_->TryLegacy());

  CreateLegacy();
  EXPECT_EQ(flex_id_generator_->TryLegacy(), kLegacyClientId);
}

TEST_F(FlexIdTest, SerialNumber) {
  EXPECT_FALSE(flex_id_generator_->TrySerial());

  // a too short serial should not be used
  CreateSerial(kShortSerial);
  EXPECT_FALSE(flex_id_generator_->TrySerial());

  // a known bad serial should not be used
  CreateSerial(kBadSerial);
  EXPECT_FALSE(flex_id_generator_->TrySerial());

  // a serial of only one repeated character should not be used
  CreateSerial(kRepeatedSerial);
  EXPECT_FALSE(flex_id_generator_->TrySerial());

  // a good serial should be used
  CreateSerial(kGoodSerial);
  EXPECT_EQ(flex_id_generator_->TrySerial(), kGoodSerial);
}

TEST_F(FlexIdTest, MacAddress) {
  EXPECT_FALSE(flex_id_generator_->TryMac());

  // 00:00:00:00:00:00 mac should not be used
  CreateInterface(kPriorityInterfaceName, kBadMacAddress, kPciModAlias);
  EXPECT_FALSE(flex_id_generator_->TryMac());

  // a non priority usb device should not be  used
  CreateInterface(kGoodInterfaceName, kGoodMacAddress, kUsbModAlias);
  EXPECT_FALSE(flex_id_generator_->TryMac());

  // a blocked interface should not be used
  CreateInterface(kBadInterfaceName, kGoodMacAddress, kPciModAlias);
  EXPECT_FALSE(flex_id_generator_->TryMac());

  // eth0 should be used
  CreateInterface(kPriorityInterfaceName, kGoodMacAddress, kPciModAlias);
  EXPECT_EQ(flex_id_generator_->TryMac(), kGoodMacAddress);
}

TEST_F(FlexIdTest, Uuid) {
  EXPECT_FALSE(flex_id_generator_->TryUuid());

  CreateUuid();
  EXPECT_EQ(flex_id_generator_->TryUuid(), kUuid);
}

TEST_F(FlexIdTest, FlexId) {
  // no flex_id should return false
  DeleteFlexId();
  EXPECT_FALSE(flex_id_generator_->ReadFlexId());

  // a blank flex_id should return false
  DeleteFlexId();
  CreateFlexId("");
  EXPECT_FALSE(flex_id_generator_->ReadFlexId());

  // a valid flex_id should be used if present
  DeleteFlexId();
  CreateFlexId(kGoodFlexId);
  EXPECT_EQ(flex_id_generator_->ReadFlexId(), kGoodFlexId);
}

TEST_F(FlexIdTest, GenerateAndSaveFlexId) {
  // no flex_id should be generated if there are no sources
  EXPECT_FALSE(flex_id_generator_->GenerateAndSaveFlexId());

  // uuid should be used for the flex_id
  CreateUuid();
  EXPECT_TRUE(flex_id_generator_->GenerateAndSaveFlexId());
  EXPECT_EQ(flex_id_generator_->ReadFlexId().value(),
            flex_id_generator_->AddFlexIdPrefix(kUuid).value());

  // a bad interface should not be used
  DeleteFlexId();
  CreateInterface(kGoodInterfaceName, kGoodMacAddress, kUsbModAlias);
  EXPECT_TRUE(flex_id_generator_->GenerateAndSaveFlexId());
  EXPECT_EQ(flex_id_generator_->ReadFlexId().value(),
            flex_id_generator_->AddFlexIdPrefix(kUuid).value());

  // a good interface should take priority over uuid
  DeleteFlexId();
  CreateInterface(kGoodInterfaceName, kGoodMacAddress, kPciModAlias);
  EXPECT_TRUE(flex_id_generator_->GenerateAndSaveFlexId());
  EXPECT_EQ(flex_id_generator_->ReadFlexId().value(),
            flex_id_generator_->AddFlexIdPrefix(kGoodMacAddress).value());

  // a priority interface should take priority over a good interface
  DeleteFlexId();
  CreateInterface(kPriorityInterfaceName, kGoodMacAddress2, kPciModAlias);
  EXPECT_TRUE(flex_id_generator_->GenerateAndSaveFlexId());
  EXPECT_EQ(flex_id_generator_->ReadFlexId().value(),
            flex_id_generator_->AddFlexIdPrefix(kGoodMacAddress2).value());

  // a bad serial should not be used
  DeleteFlexId();
  CreateSerial(kBadSerial);
  EXPECT_TRUE(flex_id_generator_->GenerateAndSaveFlexId());
  EXPECT_EQ(flex_id_generator_->ReadFlexId().value(),
            flex_id_generator_->AddFlexIdPrefix(kGoodMacAddress2).value());

  // a good serial should take priority over mac address
  DeleteFlexId();
  CreateSerial(kGoodSerial);
  EXPECT_TRUE(flex_id_generator_->GenerateAndSaveFlexId());
  EXPECT_EQ(flex_id_generator_->ReadFlexId().value(), kGoodSerial);

  // legacy client_id should take priority over a good serial
  DeleteFlexId();
  CreateLegacy();
  EXPECT_TRUE(flex_id_generator_->GenerateAndSaveFlexId());
  EXPECT_EQ(flex_id_generator_->ReadFlexId().value(), kLegacyClientId);

  // client_id should take priority over a legacy client_id
  DeleteFlexId();
  CreateClientId();
  EXPECT_TRUE(flex_id_generator_->GenerateAndSaveFlexId());
  EXPECT_EQ(flex_id_generator_->ReadFlexId().value(), kClientId);
}

}  // namespace flex_id
