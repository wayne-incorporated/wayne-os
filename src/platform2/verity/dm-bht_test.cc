// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by the GPL v2 license that can
// be found in the LICENSE file.
//
// Basic unittesting of dm-bht using google-gtest.

#include <stdlib.h>

#include <string>
#include <vector>

#include <base/logging.h>
#include <gtest/gtest.h>

#include "verity/dm-bht.h"

namespace verity {

void* my_memalign(size_t boundary, size_t size) {
  void* memptr;
  if (posix_memalign(&memptr, boundary, size))
    return NULL;
  return memptr;
}

TEST(DmBht, CreateFailOnOverflow) {
  struct dm_bht bht;
  EXPECT_EQ(-EINVAL, dm_bht_create(&bht, UINT_MAX, "sha256"));
}

TEST(DmBht, BadAlgorithmName) {
  struct dm_bht bht;
  EXPECT_EQ(-EINVAL, dm_bht_create(&bht, 10, "foo"));
}

// Simple test to help valgrind/tcmalloc catch bad mem management
TEST(DmBht, CreateZeroPopulateDestroy) {
  struct dm_bht bht;
  sector_t sectors;
  // This should fail.
  unsigned int blocks, total_blocks = 16384;
  uint8_t* data = static_cast<uint8_t*>(my_memalign(PAGE_SIZE, PAGE_SIZE));

  blocks = total_blocks;

  // Store all the block hashes of blocks of 0.
  memset(reinterpret_cast<void*>(data), 0, sizeof(data));
  EXPECT_EQ(0, dm_bht_create(&bht, blocks, "sha256"));
  dm_bht_set_read_cb(&bht, dm_bht_zeroread_callback);
  sectors = dm_bht_sectors(&bht);
  std::vector<uint8_t> hash_data(verity_to_bytes(sectors));
  dm_bht_set_buffer(&bht, hash_data.data());

  do {
    EXPECT_EQ(dm_bht_store_block(&bht, blocks - 1, data), 0);
  } while (--blocks > 0);
  // Load the tree from the pre-populated hash data
  for (blocks = 0; blocks < total_blocks; blocks += bht.node_count)
    EXPECT_GE(dm_bht_populate(&bht, reinterpret_cast<void*>(this), blocks), 0);
  EXPECT_EQ(0, dm_bht_compute(&bht));
  EXPECT_EQ(0, dm_bht_destroy(&bht));
  free(data);
}

class MemoryBhtTest : public ::testing::Test {
 public:
  void SetUp() { bht_ = NULL; }

  void TearDown() {
    hash_data_.clear();
    if (bht_)
      delete bht_;
    bht_ = NULL;
  }

  int Read(sector_t start, uint8_t* dst, sector_t count) {
    EXPECT_LT(start, sectors_);
    EXPECT_EQ(verity_to_bytes(count), PAGE_SIZE);
    uint8_t* src = &hash_data_[verity_to_bytes(start)];
    memcpy(dst, src, verity_to_bytes(count));
    return 0;
  }

  static int ReadCallback(void* mbht_instance,
                          sector_t start,
                          uint8_t* dst,
                          sector_t count,
                          struct dm_bht_entry* entry) {
    MemoryBhtTest* mbht = reinterpret_cast<MemoryBhtTest*>(mbht_instance);
    mbht->Read(start, dst, count);
    dm_bht_read_completed(entry, 0);
    return 0;
  }

 protected:
  // Creates a new dm_bht and sets it in the existing MemoryBht.
  void SetupHash(const unsigned int total_blocks,
                 const char* digest_algorithm,
                 const char* salt,
                 void* hash_data) {
    struct dm_bht bht;
    uint8_t* data = static_cast<uint8_t*>(my_memalign(PAGE_SIZE, PAGE_SIZE));

    memset(data, 0, PAGE_SIZE);

    EXPECT_EQ(0, dm_bht_create(&bht, total_blocks, digest_algorithm));
    if (salt)
      dm_bht_set_salt(&bht, salt);
    dm_bht_set_buffer(&bht, hash_data);

    unsigned int blocks = total_blocks;
    do {
      EXPECT_EQ(dm_bht_store_block(&bht, blocks - 1, data), 0);
    } while (--blocks > 0);

    EXPECT_EQ(0, dm_bht_compute(&bht));

    uint8_t digest[1024];
    dm_bht_root_hexdigest(&bht, digest, sizeof(digest));
    LOG(INFO) << "MemoryBhtTest root is " << digest;

    EXPECT_EQ(0, dm_bht_destroy(&bht));
    free(data);
  }
  void SetupBht(const unsigned int total_blocks,
                const char* digest_algorithm,
                const char* salt) {
    if (bht_)
      delete bht_;
    bht_ = new dm_bht;

    EXPECT_EQ(0, dm_bht_create(bht_, total_blocks, digest_algorithm));
    sectors_ = dm_bht_sectors(bht_);
    hash_data_.resize(verity_to_bytes(sectors_));

    if (salt)
      dm_bht_set_salt(bht_, salt);

    SetupHash(total_blocks, digest_algorithm, salt, &hash_data_[0]);
    dm_bht_set_read_cb(bht_, MemoryBhtTest::ReadCallback);

    // Load the tree from the pre-populated hash data
    unsigned int blocks;
    for (blocks = 0; blocks < total_blocks; blocks += bht_->node_count)
      EXPECT_GE(dm_bht_populate(bht_, reinterpret_cast<void*>(this), blocks),
                0);
  }

  struct dm_bht* bht_;
  std::vector<uint8_t> hash_data_;
  sector_t sectors_;
};

TEST_F(MemoryBhtTest, CreateThenVerifyOk) {
  static const unsigned int total_blocks = 16384;
  // Set the root hash for a 0-filled image
  static const char kRootDigest[] =
      "45d65d6f9e5a962f4d80b5f1bd7a918152251c27bdad8c5f52b590c129833372";
  // A page of all zeros
  uint8_t* zero_page = static_cast<uint8_t*>(my_memalign(PAGE_SIZE, PAGE_SIZE));

  memset(zero_page, 0, PAGE_SIZE);

  SetupBht(total_blocks, "sha256", NULL);
  dm_bht_set_root_hexdigest(bht_,
                            reinterpret_cast<const uint8_t*>(kRootDigest));

  for (unsigned int blocks = 0; blocks < total_blocks; ++blocks) {
    EXPECT_EQ(0, dm_bht_verify_block(bht_, blocks, zero_page, 0));
  }

  EXPECT_EQ(0, dm_bht_destroy(bht_));
  free(zero_page);
}

TEST_F(MemoryBhtTest, CreateThenVerifySingleLevel) {
  static const unsigned int total_blocks = 32;
  // Set the root hash for a 0-filled image
  static const char kRootDigest[] =
      "2d3a43008286f56536fa24dcdbf14d342f0548827e374210415c7be0b610d2ba";
  // A page of all zeros
  uint8_t* zero_page = static_cast<uint8_t*>(my_memalign(PAGE_SIZE, PAGE_SIZE));

  memset(zero_page, 0, PAGE_SIZE);

  SetupBht(total_blocks, "sha256", NULL);
  dm_bht_set_root_hexdigest(bht_,
                            reinterpret_cast<const uint8_t*>(kRootDigest));

  for (unsigned int blocks = 0; blocks < total_blocks; ++blocks) {
    EXPECT_EQ(0, dm_bht_verify_block(bht_, blocks, zero_page, 0));
  }

  EXPECT_EQ(0, dm_bht_destroy(bht_));
  free(zero_page);
}

TEST_F(MemoryBhtTest, CreateThenVerifyRealParameters) {
  static const unsigned int total_blocks = 217600;
  // Set the root hash for a 0-filled image
  static const char kRootDigest[] =
      "15d5a180b5080a1d43e3fbd1f2cd021d0fc3ea91a8e330bad468b980c2fd4d8b";
  // A page of all zeros
  uint8_t* zero_page = static_cast<uint8_t*>(my_memalign(PAGE_SIZE, PAGE_SIZE));

  memset(zero_page, 0, PAGE_SIZE);

  SetupBht(total_blocks, "sha256", NULL);
  dm_bht_set_root_hexdigest(bht_,
                            reinterpret_cast<const uint8_t*>(kRootDigest));

  for (unsigned int blocks = 0; blocks < total_blocks; ++blocks) {
    EXPECT_EQ(0, dm_bht_verify_block(bht_, blocks, zero_page, 0));
  }

  EXPECT_EQ(0, dm_bht_destroy(bht_));
  free(zero_page);
}

TEST_F(MemoryBhtTest, CreateThenVerifyOddLeafCount) {
  static const unsigned int total_blocks = 16383;
  // Set the root hash for a 0-filled image
  static const char kRootDigest[] =
      "dc8cec4220d388b05ba75c853f858bb8cc25edfb1d5d2f3be6bdf9edfa66dc6a";
  // A page of all zeros
  uint8_t* zero_page = static_cast<uint8_t*>(my_memalign(PAGE_SIZE, PAGE_SIZE));

  memset(zero_page, 0, PAGE_SIZE);

  SetupBht(total_blocks, "sha256", NULL);
  dm_bht_set_root_hexdigest(bht_,
                            reinterpret_cast<const uint8_t*>(kRootDigest));

  for (unsigned int blocks = 0; blocks < total_blocks; ++blocks) {
    EXPECT_EQ(0, dm_bht_verify_block(bht_, blocks, zero_page, 0));
  }

  EXPECT_EQ(0, dm_bht_destroy(bht_));
  free(zero_page);
}

TEST_F(MemoryBhtTest, CreateThenVerifyOddNodeCount) {
  static const unsigned int total_blocks = 16000;
  // Set the root hash for a 0-filled image
  static const char kRootDigest[] =
      "10832dd62c427bcf68c56c8de0d1f9c32b61d9e5ddf43c77c56a97b372ad4b07";
  // A page of all zeros
  uint8_t* zero_page = static_cast<uint8_t*>(my_memalign(PAGE_SIZE, PAGE_SIZE));

  memset(zero_page, 0, PAGE_SIZE);

  SetupBht(total_blocks, "sha256", NULL);
  dm_bht_set_root_hexdigest(bht_,
                            reinterpret_cast<const uint8_t*>(kRootDigest));

  for (unsigned int blocks = 0; blocks < total_blocks; ++blocks) {
    EXPECT_EQ(0, dm_bht_verify_block(bht_, blocks, zero_page, 0));
  }

  EXPECT_EQ(0, dm_bht_destroy(bht_));
  free(zero_page);
}

TEST_F(MemoryBhtTest, CreateThenVerifyBadHashBlock) {
  static const unsigned int total_blocks = 16384;
  // Set the root hash for a 0-filled image
  static const char kRootDigest[] =
      "45d65d6f9e5a962f4d80b5f1bd7a918152251c27bdad8c5f52b590c129833372";
  // A page of all zeros
  uint8_t* zero_page = static_cast<uint8_t*>(my_memalign(PAGE_SIZE, PAGE_SIZE));

  memset(zero_page, 0, PAGE_SIZE);

  SetupBht(total_blocks, "sha256", NULL);

  dm_bht_set_root_hexdigest(bht_,
                            reinterpret_cast<const uint8_t*>(kRootDigest));

  // TODO(wad) add tests for partial tree validity/verification

  // Corrupt one has hblock
  static const unsigned int kBadBlock = 256;
  uint8_t* bad_hash_block =
      static_cast<uint8_t*>(my_memalign(PAGE_SIZE, PAGE_SIZE));
  memset(bad_hash_block, 'A', PAGE_SIZE);
  EXPECT_EQ(dm_bht_store_block(bht_, kBadBlock, bad_hash_block), 0);

  // Attempt to verify both the bad block and all the neighbors.
  EXPECT_LT(dm_bht_verify_block(bht_, kBadBlock + 1, zero_page, 0), 0);
  EXPECT_LT(dm_bht_verify_block(bht_, kBadBlock + 2, zero_page, 0), 0);
  EXPECT_LT(dm_bht_verify_block(bht_, kBadBlock + (bht_->node_count / 2),
                                zero_page, 0),
            0);
  EXPECT_LT(dm_bht_verify_block(bht_, kBadBlock, zero_page, 0), 0);

  // Verify that the prior entry is untouched and still safe
  EXPECT_EQ(dm_bht_verify_block(bht_, kBadBlock - 1, zero_page, 0), 0);

  // Same for the next entry
  EXPECT_EQ(
      dm_bht_verify_block(bht_, kBadBlock + bht_->node_count, zero_page, 0), 0);

  EXPECT_EQ(0, dm_bht_destroy(bht_));
  free(bad_hash_block);
  free(zero_page);
}

TEST_F(MemoryBhtTest, CreateThenVerifyBadDataBlock) {
  static const unsigned int total_blocks = 384;
  SetupBht(total_blocks, "sha256", NULL);
  // Set the root hash for a 0-filled image
  static const char kRootDigest[] =
      "45d65d6f9e5a962f4d80b5f1bd7a918152251c27bdad8c5f52b590c129833372";
  dm_bht_set_root_hexdigest(bht_,
                            reinterpret_cast<const uint8_t*>(kRootDigest));
  // A corrupt page
  uint8_t* bad_page = static_cast<uint8_t*>(my_memalign(PAGE_SIZE, PAGE_SIZE));

  memset(bad_page, 'A', PAGE_SIZE);

  EXPECT_LT(dm_bht_verify_block(bht_, 0, bad_page, 0), 0);
  EXPECT_LT(dm_bht_verify_block(bht_, 127, bad_page, 0), 0);
  EXPECT_LT(dm_bht_verify_block(bht_, 128, bad_page, 0), 0);
  EXPECT_LT(dm_bht_verify_block(bht_, 255, bad_page, 0), 0);
  EXPECT_LT(dm_bht_verify_block(bht_, 256, bad_page, 0), 0);
  EXPECT_LT(dm_bht_verify_block(bht_, 383, bad_page, 0), 0);

  EXPECT_EQ(0, dm_bht_destroy(bht_));
  free(bad_page);
}

TEST_F(MemoryBhtTest, CreateThenVerifyOkSalt) {
  static const unsigned int total_blocks = 16384;
  // Set the root hash for a 0-filled image
  static const char kRootDigest[] =
      "8015fea349568f5135ecc833bbc79c9179377207382b53c68d93190b286b1256";
  static const char salt[] =
      "01ad1f06255d452d91337bf037953053cc3e452541db4b8ca05811bf3e2b6027";
  // A page of all zeros
  uint8_t* zero_page = static_cast<uint8_t*>(my_memalign(PAGE_SIZE, PAGE_SIZE));

  memset(zero_page, 0, PAGE_SIZE);

  SetupBht(total_blocks, "sha256", salt);
  dm_bht_set_root_hexdigest(bht_,
                            reinterpret_cast<const uint8_t*>(kRootDigest));

  for (unsigned int blocks = 0; blocks < total_blocks; ++blocks) {
    EXPECT_EQ(0, dm_bht_verify_block(bht_, blocks, zero_page, 0));
  }

  EXPECT_EQ(0, dm_bht_destroy(bht_));
  free(zero_page);
}

TEST_F(MemoryBhtTest, CreateThenVerifyOkLongSalt) {
  static const unsigned int total_blocks = 16384;
  // Set the root hash for a 0-filled image
  static const char kRootDigest[] =
      "8015fea349568f5135ecc833bbc79c9179377207382b53c68d93190b286b1256";
  static const char salt[] =
      "01ad1f06255d452d91337bf037953053cc3e452541db4b8ca05811bf3e2b6027b2188a1"
      "d";
  // A page of all zeros
  uint8_t* zero_page = static_cast<uint8_t*>(my_memalign(PAGE_SIZE, PAGE_SIZE));

  memset(zero_page, 0, PAGE_SIZE);

  SetupBht(total_blocks, "sha256", salt);
  dm_bht_set_root_hexdigest(bht_,
                            reinterpret_cast<const uint8_t*>(kRootDigest));

  for (unsigned int blocks = 0; blocks < total_blocks; ++blocks) {
    EXPECT_EQ(0, dm_bht_verify_block(bht_, blocks, zero_page, 0));
  }

  EXPECT_EQ(0, dm_bht_destroy(bht_));
  free(zero_page);
}

}  // namespace verity
