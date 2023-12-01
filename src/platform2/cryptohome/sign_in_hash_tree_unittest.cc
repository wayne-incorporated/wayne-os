// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Unit tests for SignInHashTree.

#include <utility>

#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest_prod.h>
#include <gmock/gmock.h>

#include "cryptohome/sign_in_hash_tree.h"

using ::testing::_;
using ::testing::Expectation;
using ::testing::Return;
using ::testing::SetArgPointee;

namespace cryptohome {

namespace {
// The following constant names have the format:
//  kAuxLabels<l>_<k>_<constant_number>
const char kAuxKey4_2_1[] = "1100";
const std::vector<std::string> kAuxLabels4_2_1 = {{"1101", "111", "10", "0"}};
const char kAuxKey4_2_2[] = "0111";
const std::vector<std::string> kAuxLabels4_2_2 = {{"0110", "010", "00", "1"}};
const char kAuxKey6_4_1[] = "010110";
const std::vector<std::string> kAuxLabels6_4_1 = {
    {"010100", "010101", "010111", "0100", "0110", "0111", "00", "10", "11"}};
const char kAuxKey6_4_2[] = "000010";
const std::vector<std::string> kAuxLabels6_4_2 = {
    {"000000", "000001", "000011", "0001", "0010", "0011", "01", "10", "11"}};
const std::vector<uint8_t> kRootHash4_2 = {
    {0x53, 0x6D, 0x98, 0x83, 0x7F, 0x2D, 0xD1, 0x65, 0xA5, 0x5D, 0x5E,
     0xEA, 0xE9, 0x14, 0x85, 0x95, 0x44, 0x72, 0xD5, 0x6F, 0x24, 0x6D,
     0xF2, 0x56, 0xBF, 0x3C, 0xAE, 0x19, 0x35, 0x2A, 0x12, 0x3c}};

const std::vector<uint8_t> kSampleHash1 = {
    {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x1, 0x2, 0x3,
     0x4, 0x5, 0x6, 0x7, 0x8, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6,
     0x7, 0x8, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8}};

const std::vector<uint8_t> kRootHash6_4_1 = {
    {0x42, 0xA8, 0x59, 0x26, 0xBA, 0xF5, 0x62, 0xFB, 0x10, 0xCC, 0x33,
     0x79, 0x66, 0xA5, 0xC4, 0x74, 0xD1, 0x81, 0x44, 0x08, 0xB4, 0x78,
     0xA7, 0x92, 0x1E, 0x07, 0x89, 0xBB, 0x9A, 0x8D, 0xBC, 0x02}};

const std::vector<uint8_t> kRootHash14_4_1 = {
    {0x91, 0x3C, 0xA7, 0x20, 0x82, 0x23, 0xB8, 0xC8, 0x92, 0xA6, 0x1E,
     0x83, 0xD9, 0x68, 0x07, 0x28, 0xE3, 0xE1, 0xD6, 0xBB, 0x10, 0x63,
     0xF2, 0xDD, 0xCE, 0x92, 0x25, 0x71, 0x80, 0x3D, 0xA9, 0xEE}};

const std::vector<uint8_t> kRootHash14_4_2 = {
    {0x59, 0x72, 0x23, 0x5E, 0xF3, 0x89, 0x4B, 0xE6, 0x6B, 0x59, 0x97,
     0x22, 0xCC, 0x95, 0xC8, 0xEC, 0xB8, 0x74, 0x0E, 0x97, 0x3C, 0x77,
     0x60, 0x41, 0xB4, 0x50, 0x4F, 0xE8, 0xCA, 0x4E, 0x71, 0x05}};

const std::vector<uint8_t> kSampleCredData1 = {{0xA, 0xB, 0xC, 0xD}};

std::vector<std::string> ConvertLabelsIntoStrings(
    const std::vector<SignInHashTree::Label>& labels) {
  std::vector<std::string> result_strings;
  for (auto const& label : labels) {
    result_strings.push_back(
        std::bitset<64>(label.value()).to_string().substr(64 - label.length()));
  }
  return result_strings;
}

}  // namespace

TEST(SignInHashTreeUnitTest, GetAuxiliaryLabelsTest) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());

  SignInHashTree tree(4, 1, temp_dir.GetPath());

  // Convert the string labels into Label which the code understands.
  uint64_t key_val = static_cast<uint64_t>(std::stoi(kAuxKey4_2_1, nullptr, 2));
  auto label = SignInHashTree::Label(key_val, 4, 1);
  auto result_labels = tree.GetAuxiliaryLabels(label);
  // Convert the labels into strings for easy comparison.
  EXPECT_EQ(kAuxLabels4_2_1, ConvertLabelsIntoStrings(result_labels));

  key_val = static_cast<uint64_t>(std::stoi(kAuxKey4_2_2, nullptr, 2));
  label = SignInHashTree::Label(key_val, 4, 1);
  result_labels = tree.GetAuxiliaryLabels(label);
  EXPECT_EQ(kAuxLabels4_2_2, ConvertLabelsIntoStrings(result_labels));

  base::ScopedTempDir temp_dir2;
  ASSERT_TRUE(temp_dir2.CreateUniqueTempDir());

  SignInHashTree tree2(6, 2, temp_dir2.GetPath());

  key_val = static_cast<uint64_t>(std::stoi(kAuxKey6_4_1, nullptr, 2));
  label = SignInHashTree::Label(key_val, 6, 2);
  result_labels = tree2.GetAuxiliaryLabels(label);
  EXPECT_EQ(kAuxLabels6_4_1, ConvertLabelsIntoStrings(result_labels));

  key_val = static_cast<uint64_t>(std::stoi(kAuxKey6_4_2, nullptr, 2));
  label = SignInHashTree::Label(key_val, 6, 2);
  result_labels = tree2.GetAuxiliaryLabels(label);
  EXPECT_EQ(kAuxLabels6_4_2, ConvertLabelsIntoStrings(result_labels));
}

// Test that we can generate a hash file with an expected root hash.
// Also test that we can write to the hash file and read back from it
// when we update an inner label.
TEST(SignInHashTreeUnitTest, GenerateAndStoreHashCacheFile) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());

  SignInHashTree tree(4, 1, temp_dir.GetPath());
  tree.GenerateAndStoreHashCache();

  // Check that the root hash was calculated successfully.
  std::vector<uint8_t> result_hash;
  std::vector<uint8_t> cred_data;
  bool metadata_lost = false;
  auto label = SignInHashTree::Label(0, 0, 1);
  ASSERT_TRUE(
      tree.GetLabelData(label, &result_hash, &cred_data, &metadata_lost));
  EXPECT_EQ(kRootHash4_2, result_hash);

  // Try updating Label "00".
  ASSERT_TRUE(tree.StoreLabel(SignInHashTree::Label(0, 2, 1), kSampleHash1,
                              cred_data, false));
  // Try updating Label "101".
  ASSERT_TRUE(tree.StoreLabel(SignInHashTree::Label(5, 3, 1), kSampleHash1,
                              cred_data, false));

  result_hash.clear();
  ASSERT_TRUE(tree.GetLabelData(SignInHashTree::Label(0, 2, 1), &result_hash,
                                &cred_data, &metadata_lost));
  EXPECT_EQ(kSampleHash1, result_hash);
  EXPECT_EQ(false, metadata_lost);
  result_hash.clear();
  ASSERT_TRUE(tree.GetLabelData(SignInHashTree::Label(5, 3, 1), &result_hash,
                                &cred_data, &metadata_lost));
  EXPECT_EQ(kSampleHash1, result_hash);
  EXPECT_EQ(false, metadata_lost);
}

// Test that we can insert and retrieve a leaf label when we initialize
// a SignInHashTree. Also make sure the hash tree can understand that
// the label has been taken. Also test that once we re-initialize a
// SignInHashTree, it will have the correct label entry, and the
// root hash will also be what we expect.
TEST(SignInHashTreeUnitTest, InsertAndRetrieveLeafLabel) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());

  auto tree = std::make_unique<SignInHashTree>(6, 2, temp_dir.GetPath());
  tree->GenerateAndStoreHashCache();

  ASSERT_TRUE(tree->StoreLabel(SignInHashTree::Label(21, 6, 2), kSampleHash1,
                               kSampleCredData1, false));
  std::vector<uint8_t> returned_hash, cred_data;
  bool metadata_lost = true;
  ASSERT_TRUE(tree->GetLabelData(SignInHashTree::Label(21, 6, 2),
                                 &returned_hash, &cred_data, &metadata_lost));
  EXPECT_EQ(kSampleHash1, returned_hash);
  EXPECT_EQ(kSampleCredData1, cred_data);
  EXPECT_EQ(false, metadata_lost);

  // Try the insert and retrieve for invalid labels too.
  returned_hash.clear();
  cred_data.clear();
  metadata_lost = false;
  ASSERT_TRUE(tree->StoreLabel(SignInHashTree::Label(21, 6, 2), kSampleHash1,
                               kSampleCredData1, true));
  ASSERT_TRUE(tree->GetLabelData(SignInHashTree::Label(21, 6, 2),
                                 &returned_hash, &cred_data, &metadata_lost));
  EXPECT_EQ(kSampleHash1, returned_hash);
  EXPECT_EQ(true, metadata_lost);

  // Regenerate the hash cache so the root hash gets recalculated.
  tree->GenerateAndStoreHashCache();

  returned_hash.clear();
  cred_data.clear();
  ASSERT_TRUE(tree->GetLabelData(SignInHashTree::Label(0, 0, 2), &returned_hash,
                                 &cred_data, &metadata_lost));
  EXPECT_EQ(kRootHash6_4_1, returned_hash);
  returned_hash.clear();
  tree->GetRootHash(&returned_hash);
  EXPECT_EQ(kRootHash6_4_1, returned_hash);
}

// Test another hash tree, and check that when you insert / remove a label,
// the |hash_cache_| gets updated without having to call
// GenerateAndStoreHsahCache on the entire tree.
TEST(SignInHashTreeUnitTest, UpdateHashCacheOnInsertRemove) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());

  // Create initial table and HashCache.
  auto tree = std::make_unique<SignInHashTree>(14, 2, temp_dir.GetPath());
  tree->GenerateAndStoreHashCache();

  std::vector<uint8_t> returned_hash, cred_data;
  bool metadata_lost = false;
  ASSERT_TRUE(tree->GetLabelData(SignInHashTree::Label(0, 0, 2), &returned_hash,
                                 &cred_data, &metadata_lost));
  ASSERT_EQ(kRootHash14_4_1, returned_hash);

  // Insert a label.
  ASSERT_TRUE(tree->StoreLabel(SignInHashTree::Label(21, 14, 2), kSampleHash1,
                               kSampleCredData1, false));
  returned_hash.clear();
  tree->GetRootHash(&returned_hash);
  EXPECT_EQ(kRootHash14_4_2, returned_hash);

  // Remove the label; the root hash should be what it was earlier.
  ASSERT_TRUE(tree->RemoveLabel(SignInHashTree::Label(21, 14, 2)));
  returned_hash.clear();
  tree->GetRootHash(&returned_hash);
  EXPECT_EQ(kRootHash14_4_1, returned_hash);
}

}  // namespace cryptohome
