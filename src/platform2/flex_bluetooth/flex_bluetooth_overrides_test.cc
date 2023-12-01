// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "flex_bluetooth/flex_bluetooth_overrides.h"

#include <string>

#include <base/check.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

namespace flex_bluetooth {

class FlexBluetoothOverridesTest : public ::testing::Test {
  void SetUp() override {
    CHECK(temp_dir_.CreateUniqueTempDir());
    filepath_ = temp_dir_.GetPath().Append("syspropsoverride.conf");
  }

 protected:
  base::ScopedTempDir temp_dir_;
  base::FilePath filepath_;
};

TEST_F(FlexBluetoothOverridesTest, SyspropOverrideExistence) {
  const uint16_t id_vendor_a = 0x0cf3;
  const uint16_t id_product_a = 0xe007;
  std::map<BluetoothAdapter, std::unordered_set<SyspropOverride>> overrides = {
      {BluetoothAdapter{id_vendor_a, id_product_a},
       {SyspropOverride::kDisableLEGetVendorCapabilities}},
  };

  // Test that we found the one override we put in the map
  const FlexBluetoothOverrides bt(base::FilePath(filepath_), overrides);
  const auto overrides_a =
      bt.GetAdapterSyspropOverridesForVidPid(id_vendor_a, id_product_a);
  EXPECT_EQ(overrides_a.size(), 1);
  EXPECT_EQ(overrides_a.count(SyspropOverride::kDisableLEGetVendorCapabilities),
            1);

  bt.ProcessOverridesForVidPid(id_vendor_a, id_product_a);
  std::string contents_a;
  ASSERT_TRUE(base::ReadFileToString(filepath_, &contents_a));
  EXPECT_EQ(
      contents_a,
      "[Sysprops]\nbluetooth.core.le.vendor_capabilities.enabled=false\n");

  // Test that we don't get any overrides if the id_vendor is the same but the
  // id_product is different
  const uint16_t id_vendor_b = id_vendor_a;
  const uint16_t id_product_b = id_product_a + 1;
  const auto overrides_b =
      bt.GetAdapterSyspropOverridesForVidPid(id_vendor_b, id_product_b);
  EXPECT_TRUE(overrides_b.empty());
  bt.ProcessOverridesForVidPid(id_vendor_b, id_product_b);
  std::string contents_b;
  ASSERT_TRUE(base::ReadFileToString(filepath_, &contents_b));
  EXPECT_EQ(contents_b, "[Sysprops]\n");

  // Test that we don't get any overrides if the id_vendor is different but the
  // id_product is the same
  const uint16_t id_vendor_c = id_vendor_a + 1;
  const uint16_t id_product_c = id_product_a;
  const auto overrides_c =
      bt.GetAdapterSyspropOverridesForVidPid(id_vendor_c, id_product_c);
  EXPECT_TRUE(overrides_c.empty());
  bt.ProcessOverridesForVidPid(id_vendor_c, id_product_c);
  std::string contents_c;
  ASSERT_TRUE(base::ReadFileToString(filepath_, &contents_c));
  EXPECT_EQ(contents_c, "[Sysprops]\n");

  // Test that we don't get any overrides if the id_vendor is different and the
  // id_product is different
  const uint16_t id_vendor_d = id_vendor_a + 1;
  const uint16_t id_product_d = id_product_a + 1;
  const auto overrides_d =
      bt.GetAdapterSyspropOverridesForVidPid(id_vendor_d, id_product_d);
  EXPECT_TRUE(overrides_d.empty());
  bt.ProcessOverridesForVidPid(id_vendor_d, id_product_d);
  std::string contents_d;
  ASSERT_TRUE(base::ReadFileToString(filepath_, &contents_d));
  EXPECT_EQ(contents_d, "[Sysprops]\n");
}

TEST_F(FlexBluetoothOverridesTest, RemoveSyspropOverrideFile) {
  const uint16_t id_vendor_a = 0x0cf3;
  const uint16_t id_product_a = 0xe007;
  std::map<BluetoothAdapter, std::unordered_set<SyspropOverride>> overrides = {
      {BluetoothAdapter{id_vendor_a, id_product_a},
       {SyspropOverride::kDisableLEGetVendorCapabilities}},
  };
  const FlexBluetoothOverrides bt(base::FilePath(filepath_), overrides);
  const auto overrides_a =
      bt.GetAdapterSyspropOverridesForVidPid(id_vendor_a, id_product_a);
  EXPECT_EQ(overrides_a.size(), 1);
  EXPECT_EQ(overrides_a.count(SyspropOverride::kDisableLEGetVendorCapabilities),
            1);

  bt.ProcessOverridesForVidPid(id_vendor_a, id_product_a);
  std::string contents_a;
  ASSERT_TRUE(base::ReadFileToString(filepath_, &contents_a));
  EXPECT_EQ(
      contents_a,
      "[Sysprops]\nbluetooth.core.le.vendor_capabilities.enabled=false\n");

  // Remove
  bt.RemoveOverrides();
  ASSERT_TRUE(base::ReadFileToString(filepath_, &contents_a));
  EXPECT_EQ(contents_a, "");
}

TEST_F(FlexBluetoothOverridesTest, HexStringToUInt16) {
  uint16_t value;

  // Invalid: too high
  EXPECT_FALSE(HexStringToUInt16("10000", &value));
  EXPECT_FALSE(HexStringToUInt16("ffffffff", &value));

  // Valid
  EXPECT_TRUE(HexStringToUInt16("00", &value));
  EXPECT_EQ(value, 0);

  EXPECT_TRUE(HexStringToUInt16("ffff", &value));
  EXPECT_EQ(value, 65535);
}

}  // namespace flex_bluetooth
