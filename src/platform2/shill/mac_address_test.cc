// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "shill/mac_address.h"

#include <cstdio>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "base/rand_util.h"
#include "shill/store/fake_store.h"

using testing::Test;

namespace shill {

class MACAddressTest : public Test {
 public:
  MACAddressTest() : storage_id_("device_1234") {}
  ~MACAddressTest() override = default;

 protected:
  std::string storage_id_;
};

TEST_F(MACAddressTest, SetClear) {
  MACAddress addr;
  EXPECT_FALSE(addr.is_set());
  EXPECT_EQ(addr.ToString(), "<UNSET>");
  addr.Set("abcd");
  EXPECT_FALSE(addr.is_set());
  addr.Set("aa:bb:cc:dd:ee:ff");
  EXPECT_TRUE(addr.is_set());
  EXPECT_EQ(addr.ToString(), "aa:bb:cc:dd:ee:ff");
  addr.Clear();
  EXPECT_FALSE(addr.is_set());
}

TEST_F(MACAddressTest, Randomize) {
  static constexpr auto kMulticastBit = 1 << 0;
  static constexpr auto kLocallyAdministeredBit = 1 << 1;
  MACAddress addr;
  EXPECT_FALSE(addr.is_set());
  EXPECT_EQ(addr.ToString(), "<UNSET>");
  addr.Randomize();
  EXPECT_TRUE(addr.is_set());
  uint8_t msb;
  EXPECT_EQ(sscanf(addr.ToString().substr(0, 2).c_str(), "%02hhx", &msb), 1);
  EXPECT_EQ(msb & (kMulticastBit | kLocallyAdministeredBit),
            kLocallyAdministeredBit);
  addr.Clear();
  EXPECT_FALSE(addr.is_set());
}

TEST_F(MACAddressTest, AddressExpire) {
  MACAddress addr;
  addr.Randomize();
  EXPECT_TRUE(addr.is_set());
  auto start_time = base::Time::FromDeltaSinceWindowsEpoch(base::Seconds(1));
  EXPECT_FALSE(addr.IsExpired(start_time));
  addr.set_expiration_time(start_time + base::Seconds(10));
  EXPECT_FALSE(addr.IsExpired(start_time));
  EXPECT_FALSE(addr.IsExpired(start_time + base::Seconds(9)));
  EXPECT_FALSE(addr.IsExpired(start_time + base::Seconds(10)));
  EXPECT_TRUE(addr.IsExpired(start_time + base::Seconds(11)));
}

TEST_F(MACAddressTest, LoadSave_Unset) {
  FakeStore storage;
  MACAddress mac_addr;

  // Verify behaviour for an unset value.
  EXPECT_FALSE(mac_addr.Save(&storage, storage_id_));
  EXPECT_FALSE(mac_addr.Load(&storage, storage_id_));
  EXPECT_FALSE(mac_addr.is_set());
}

TEST_F(MACAddressTest, LoadSave_Valid) {
  FakeStore storage;
  MACAddress mac_addr, addr;

  // Verification for a valid value.
  mac_addr.Randomize();
  EXPECT_TRUE(mac_addr.Save(&storage, storage_id_));
  EXPECT_TRUE(addr.Load(&storage, storage_id_));
  EXPECT_TRUE(addr.is_set());
  EXPECT_EQ(addr, mac_addr);
}

TEST_F(MACAddressTest, LoadSave_Expiring) {
  FakeStore storage;
  MACAddress mac_addr, addr;

  // Verification for an expiring value.
  mac_addr.Randomize();
  mac_addr.set_expiration_time(base::Time::Now() +
                               base::Seconds(base::RandInt(0, 1000)));
  EXPECT_TRUE(mac_addr.Save(&storage, storage_id_));
  EXPECT_TRUE(addr.Load(&storage, storage_id_));
  EXPECT_TRUE(addr.is_set());
  EXPECT_EQ(addr, mac_addr);
}

}  // namespace shill
