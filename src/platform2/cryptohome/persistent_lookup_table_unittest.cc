// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Unit tests for PersistentLookupTable.

#include <memory>
#include <set>
#include <string>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cryptohome/persistent_lookup_table.h"

using ::testing::_;

namespace {

const uint64_t kKey1 = 123456;
const uint64_t kKey2 = 0;
const uint64_t kKey3 = 123;
const std::vector<uint8_t> kValue1_1 = {{0x34, 0x32, 0x31}};
const std::vector<uint8_t> kValue1_2 = {{0x12, 0x13, 0x14}};
const std::vector<uint8_t> kValue1_3 = {{0xDE, 0xAD, 0xBE, 0xEF}};
const std::vector<uint8_t> kValue1_4 = {{0xED, 0xDA, 0xEB, 0xFE}};
const std::vector<uint8_t> kValue2_1 = {{0x97, 0x98, 0x99}};
const std::vector<uint8_t> kValue2_2 = {{0xAB, 0xCD, 0xEF}};
const std::vector<uint8_t> kValue2_3 = {{0xBA, 0xDC, 0xFE}};
const std::vector<uint8_t> kValue3_1 = {{0x01, 0x02, 0x03}};

}  // namespace

namespace cryptohome {

// Check whether we can successfully create a new directory for the lookup
// table at specified location. Also tests whether basic Store and Get
// operations work correctly.
TEST(PersistentLookupTableTest, CreateDirStoreValues) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());

  std::unique_ptr<Platform> platform(new Platform());
  PersistentLookupTable lookup_table(platform.get(), temp_dir.GetPath());
  lookup_table.InitOnBoot();

  // Verify basic Store and Get.
  std::vector<uint8_t> result;
  ASSERT_EQ(PLT_SUCCESS, lookup_table.StoreValue(kKey1, kValue1_1));
  EXPECT_EQ(PLT_SUCCESS, lookup_table.GetValue(kKey1, &result));
  EXPECT_EQ(kValue1_1, result);

  // Verify non-existent key returns correct values.
  result.clear();
  EXPECT_FALSE(lookup_table.KeyExists(kKey2));
  EXPECT_EQ(PLT_KEY_NOT_FOUND, lookup_table.GetValue(kKey2, &result));

  ASSERT_EQ(PLT_SUCCESS, lookup_table.StoreValue(kKey2, kValue2_1));

  // Verify overwrite of earlier key.
  result.clear();
  ASSERT_EQ(PLT_SUCCESS, lookup_table.StoreValue(kKey1, kValue1_2));
  EXPECT_EQ(PLT_SUCCESS, lookup_table.GetValue(kKey1, &result));
  EXPECT_EQ(kValue1_2, result);
}

// Check whether we can restore a pre-existing table.
TEST(PersistentLookupTableTest, RestoreTable) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());

  std::unique_ptr<Platform> platform(new Platform());
  std::unique_ptr<PersistentLookupTable> lookup_table =
      std::make_unique<PersistentLookupTable>(platform.get(),
                                              temp_dir.GetPath());
  lookup_table->InitOnBoot();

  // Add some entries.
  ASSERT_EQ(PLT_SUCCESS, lookup_table->StoreValue(kKey1, kValue1_1));
  ASSERT_EQ(PLT_SUCCESS, lookup_table->StoreValue(kKey1, kValue1_2));
  ASSERT_EQ(PLT_SUCCESS, lookup_table->StoreValue(kKey2, kValue2_1));
  ASSERT_EQ(PLT_SUCCESS, lookup_table->StoreValue(kKey3, kValue3_1));

  // Destroy old object, now instantiate a new table object and restore old
  // table.
  lookup_table.reset();
  platform = std::make_unique<Platform>();
  lookup_table = std::make_unique<PersistentLookupTable>(platform.get(),
                                                         temp_dir.GetPath());
  lookup_table->InitOnBoot();

  ASSERT_EQ(PLT_SUCCESS, lookup_table->StoreValue(kKey1, kValue1_3));
  ASSERT_EQ(PLT_SUCCESS, lookup_table->StoreValue(kKey2, kValue2_2));
  // Deleting a key (we check later whether the delete worked).
  ASSERT_EQ(PLT_SUCCESS, lookup_table->RemoveKey(kKey3));

  // Destroy it one last time, then reload it.
  lookup_table.reset();
  platform = std::make_unique<Platform>();
  lookup_table = std::make_unique<PersistentLookupTable>(platform.get(),
                                                         temp_dir.GetPath());
  lookup_table->InitOnBoot();

  // Check that the values are as expected.
  std::vector<uint8_t> result;
  EXPECT_EQ(PLT_SUCCESS, lookup_table->GetValue(kKey1, &result));
  EXPECT_EQ(kValue1_3, result);
  result.clear();
  EXPECT_EQ(PLT_SUCCESS, lookup_table->GetValue(kKey1, &result));
  EXPECT_NE(kValue1_1, result);
  result.clear();
  EXPECT_EQ(PLT_SUCCESS, lookup_table->GetValue(kKey2, &result));
  EXPECT_NE(kValue2_1, result);
  result.clear();
  EXPECT_EQ(PLT_SUCCESS, lookup_table->GetValue(kKey2, &result));
  EXPECT_EQ(kValue2_2, result);
  EXPECT_FALSE(lookup_table->KeyExists(kKey3));
  result.clear();
}

// Tests whether we can delete keys from a table.
TEST(PersistentLookupTableTest, DeleteKeys) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());

  std::unique_ptr<Platform> platform(new Platform());
  PersistentLookupTable lookup_table(platform.get(), temp_dir.GetPath());
  lookup_table.InitOnBoot();

  ASSERT_EQ(PLT_SUCCESS, lookup_table.StoreValue(kKey1, kValue1_1));
  ASSERT_EQ(PLT_SUCCESS, lookup_table.StoreValue(kKey2, kValue2_1));
  ASSERT_EQ(PLT_SUCCESS, lookup_table.StoreValue(kKey1, kValue1_2));
  ASSERT_EQ(PLT_SUCCESS, lookup_table.StoreValue(kKey1, kValue1_3));
  ASSERT_EQ(PLT_SUCCESS, lookup_table.StoreValue(kKey2, kValue2_2));
  ASSERT_EQ(PLT_SUCCESS, lookup_table.StoreValue(kKey2, kValue2_3));

  ASSERT_EQ(PLT_SUCCESS, lookup_table.RemoveKey(kKey1));
  EXPECT_FALSE(lookup_table.KeyExists(kKey1));

  std::vector<uint8_t> result;
  ASSERT_EQ(PLT_SUCCESS, lookup_table.StoreValue(kKey1, kValue1_4));
  EXPECT_EQ(PLT_SUCCESS, lookup_table.GetValue(kKey1, &result));
  EXPECT_EQ(kValue1_4, result);
}

// Tests whether we can list the number of currently used keys.
TEST(PersistentLookupTableTest, GetUsedKeys) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());

  std::unique_ptr<Platform> platform(new Platform());
  PersistentLookupTable lookup_table(platform.get(), temp_dir.GetPath());
  lookup_table.InitOnBoot();

  ASSERT_EQ(PLT_SUCCESS, lookup_table.StoreValue(kKey1, kValue1_1));
  ASSERT_EQ(PLT_SUCCESS, lookup_table.StoreValue(kKey2, kValue2_1));
  ASSERT_EQ(PLT_SUCCESS, lookup_table.StoreValue(kKey1, kValue1_2));
  ASSERT_EQ(PLT_SUCCESS, lookup_table.StoreValue(kKey2, kValue2_2));
  ASSERT_EQ(PLT_SUCCESS, lookup_table.StoreValue(kKey3, kValue3_1));

  std::vector<uint64_t> key_list;
  lookup_table.GetUsedKeys(&key_list);
  EXPECT_EQ(std::set<uint64_t>({kKey1, kKey2, kKey3}),
            std::set<uint64_t>(key_list.begin(), key_list.end()));

  // Remove a key and make sure the number of keys is correct.
  ASSERT_EQ(PLT_SUCCESS, lookup_table.RemoveKey(kKey2));
  key_list.clear();
  lookup_table.GetUsedKeys(&key_list);
  EXPECT_EQ(std::set<uint64_t>({kKey1, kKey3}),
            std::set<uint64_t>(key_list.begin(), key_list.end()));
}

}  // namespace cryptohome
