// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Unit tests for SecureBlob.

#include "brillo/asan.h"
#include "brillo/secure_allocator.h"
#include "brillo/secure_blob.h"
#include <sys/resource.h>

#include <algorithm>
#include <iterator>
#include <limits>
#include <numeric>
#include <utility>

#include <base/check_op.h>
#include <base/logging.h>
#include <gtest/gtest.h>

namespace brillo {
using std::string;

// Tests BlobToString() and BlobFromString().
TEST(BlobTest, StringConversions) {
  const char kTestBytes[] = {'\0', '\x1', 'a', std::numeric_limits<char>::min(),
                             std::numeric_limits<char>::max()};
  const Blob blob(std::begin(kTestBytes), std::end(kTestBytes));
  const string obtained_string = BlobToString(blob);
  EXPECT_EQ(string(std::begin(kTestBytes), std::end(kTestBytes)),
            obtained_string);
  const Blob obtained_blob = BlobFromString(obtained_string);
  EXPECT_EQ(blob, obtained_blob);
}

// Tests CombineBlobs().
TEST(BlobTest, CombineBlobs) {
  const Blob kEmpty;
  const Blob kBlob1 = {1};
  const Blob kBlob2 = {2};
  const Blob kBlob3 = {3};
  const Blob kBlob12 = {1, 2};
  const Blob kBlob123 = {1, 2, 3};
  EXPECT_EQ(kBlob123, CombineBlobs({kBlob12, kBlob3}));
  EXPECT_EQ(kBlob123, CombineBlobs({kBlob1, kBlob2, kBlob3}));
  EXPECT_EQ(kBlob12, CombineBlobs({kBlob12}));
  EXPECT_EQ(kBlob12, CombineBlobs({kEmpty, kBlob1, kEmpty, kBlob2, kEmpty}));
  EXPECT_EQ(kEmpty, CombineBlobs({}));
}

class SecureBlobTest : public ::testing::Test {
 public:
  SecureBlobTest() {}
  SecureBlobTest(const SecureBlobTest&) = delete;
  SecureBlobTest& operator=(const SecureBlobTest&) = delete;

  virtual ~SecureBlobTest() {}

  static bool FindBlobInBlob(const brillo::SecureBlob& haystack,
                             const brillo::SecureBlob& needle) {
    auto pos = std::search(haystack.begin(), haystack.end(), needle.begin(),
                           needle.end());
    return (pos != haystack.end());
  }

  static int FindBlobIndexInBlob(const brillo::SecureBlob& haystack,
                                 const brillo::SecureBlob& needle) {
    auto pos = std::search(haystack.begin(), haystack.end(), needle.begin(),
                           needle.end());
    if (pos == haystack.end()) {
      return -1;
    }
    return std::distance(haystack.begin(), pos);
  }
};

TEST_F(SecureBlobTest, AllocationSizeTest) {
  // Checks that allocating a SecureBlob of a specified size works.
  SecureBlob blob(32);

  EXPECT_EQ(32, blob.size());
}

TEST_F(SecureBlobTest, ConstructorCountValueTest) {
  // Checks that constructing a SecureBlob with |count| copies of |value| works.
  SecureBlob blob(32, 'a');

  for (size_t i = 0; i < blob.size(); i++) {
    EXPECT_EQ('a', blob[i]);
  }
}

TEST_F(SecureBlobTest, ConstructorAmbiguousTest) {
  // This test will become important once SecureBlob stops inheriting from Blob.
  SecureBlob blob(32, 0);

  for (size_t i = 0; i < blob.size(); i++) {
    EXPECT_EQ(0, blob[i]);
  }
}

TEST_F(SecureBlobTest, ConstructorIteratorTest) {
  // Checks that constructing a SecureBlob with an iterator works.
  unsigned char from_data[32];
  std::iota(std::begin(from_data), std::end(from_data), 0);

  SecureBlob blob(std::begin(from_data), std::end(from_data));

  EXPECT_EQ(sizeof(from_data), blob.size());

  for (unsigned int i = 0; i < sizeof(from_data); i++) {
    EXPECT_EQ(from_data[i], blob[i]);
  }
}

TEST_F(SecureBlobTest, BlobConstructorTest) {
  // Check that constructing a SecureBlob from a Blob works.
  const std::vector<uint8_t> bytes = {0, 1, 255};
  const Blob blob(bytes);
  const SecureBlob secure_blob(blob);
  EXPECT_EQ(bytes,
            std::vector<uint8_t>(secure_blob.begin(), secure_blob.end()));
}

TEST_F(SecureBlobTest, IteratorTest) {
  // Checks that SecureBlob::begin(), SecureBlob::end() work.
  unsigned char from_data[32];
  std::iota(std::begin(from_data), std::end(from_data), 0);

  SecureBlob blob(std::begin(from_data), std::end(from_data));

  EXPECT_EQ(sizeof(from_data), blob.size());

  size_t i = 0;
  for (auto it = blob.begin(); it != blob.end(); ++it) {
    EXPECT_EQ(from_data[i], *it);
    ++i;
  }
}

TEST_F(SecureBlobTest, AssignTest) {
  // Checks that .assign() works.
  unsigned char from_data[32];
  std::iota(std::begin(from_data), std::end(from_data), 0);

  SecureBlob blob;
  blob.assign(std::begin(from_data), std::end(from_data));

  EXPECT_EQ(sizeof(from_data), blob.size());

  size_t i = 0;
  for (auto it = blob.begin(); it != blob.end(); ++it) {
    EXPECT_EQ(from_data[i], *it);
    ++i;
  }

  SecureBlob blob2;
  blob2.assign(blob.begin(), blob.end());

  EXPECT_EQ(blob, blob2);
}

// Disable ResizeTest with Address Sanitizer.
// https://crbug.com/806013
#ifndef BRILLO_ASAN_BUILD
TEST_F(SecureBlobTest, ResizeTest) {
  // Check that resizing a SecureBlob wipes the excess memory. The test assumes
  // that resize() down by one will not re-allocate the memory, so the last byte
  // will still be part of the SecureBlob's allocation.
  size_t length = 1024;
  SecureBlob blob(length);
  void* original_data = blob.data();
  for (size_t i = 0; i < length; i++) {
    blob[i] = i;
  }

  blob.resize(length - 1);

  EXPECT_EQ(original_data, blob.data());
  EXPECT_EQ(length - 1, blob.size());
  EXPECT_EQ(0, blob.data()[length - 1]);
}
#endif

TEST_F(SecureBlobTest, CombineTest) {
  SecureBlob blob1(32);
  SecureBlob blob2(32);
  std::iota(blob1.begin(), blob1.end(), 0);
  std::iota(blob2.begin(), blob2.end(), 32);
  SecureBlob combined_blob = SecureBlob::Combine(blob1, blob2);
  EXPECT_EQ(combined_blob.size(), (blob1.size() + blob2.size()));
  EXPECT_TRUE(SecureBlobTest::FindBlobInBlob(combined_blob, blob1));
  EXPECT_TRUE(SecureBlobTest::FindBlobInBlob(combined_blob, blob2));
  int blob1_index = SecureBlobTest::FindBlobIndexInBlob(combined_blob, blob1);
  int blob2_index = SecureBlobTest::FindBlobIndexInBlob(combined_blob, blob2);
  EXPECT_EQ(blob1_index, 0);
  EXPECT_EQ(blob2_index, 32);
}

TEST_F(SecureBlobTest, BlobToStringTest) {
  std::string test_string("Test String");
  SecureBlob blob = SecureBlob(test_string.begin(), test_string.end());
  EXPECT_EQ(blob.size(), test_string.length());
  std::string result_string = blob.to_string();
  EXPECT_EQ(test_string.compare(result_string), 0);
}

TEST_F(SecureBlobTest, HexStringToSecureBlob) {
  std::string hex_string("112233445566778899aabbccddeeff0f");

  SecureBlob blob;
  SecureBlob::HexStringToSecureBlob(hex_string, &blob);

  EXPECT_EQ(blob.size(), 16u);
  EXPECT_EQ(blob[0], 0x11);
  EXPECT_EQ(blob[1], 0x22);
  EXPECT_EQ(blob[2], 0x33);
  EXPECT_EQ(blob[3], 0x44);
  EXPECT_EQ(blob[4], 0x55);
  EXPECT_EQ(blob[5], 0x66);
  EXPECT_EQ(blob[6], 0x77);
  EXPECT_EQ(blob[7], 0x88);
  EXPECT_EQ(blob[8], 0x99);
  EXPECT_EQ(blob[9], 0xaa);
  EXPECT_EQ(blob[10], 0xbb);
  EXPECT_EQ(blob[11], 0xcc);
  EXPECT_EQ(blob[12], 0xdd);
  EXPECT_EQ(blob[13], 0xee);
  EXPECT_EQ(blob[14], 0xff);
  EXPECT_EQ(blob[15], 0x0f);
}

// Override clear_contents() to check whether memory has been cleared.
template <typename T>
class TestSecureAllocator : public SecureAllocator<T> {
 public:
  TestSecureAllocator() {
    erased_count = 0;
  }

  int GetErasedCount() { return erased_count; }

 protected:
  static int erased_count;

  void clear_contents(T* p, std::size_t n) override {
    SecureAllocator<T>::clear_contents(p, n);
    unsigned char* v = reinterpret_cast<unsigned char*>(p);
    for (int i = 0; i < n; i++) {
      EXPECT_EQ(v[i], 0);
      erased_count++;
    }
  }
};

template <typename T>
int TestSecureAllocator<T>::erased_count;

TEST(SecureAllocator, ErasureOnDeallocation) {
  // Make sure that the contents are cleared on deallocation.
  TestSecureAllocator<char> e;

  char* test_string_addr = e.allocate(15);
  snprintf(test_string_addr, sizeof(test_string_addr), "Test String");

  // Deallocate memory; the mock class should check for cleared data.
  e.deallocate(test_string_addr, 15);
  // The deallocation should have traversed the complete page.
  EXPECT_EQ(e.GetErasedCount(), 4096);
}

TEST(SecureAllocator, MultiPageCorrectness) {
  // Make sure that the contents are cleared on deallocation.
  TestSecureAllocator<uint64_t> e;

  // Allocate 4100*8 bytes.
  uint64_t* test_array = e.allocate(4100);

  // Check if the space was correctly allocated for long long.
  for (int i = 0; i < 4100; i++)
    test_array[i] = 0xF0F0F0F0F0F0F0F0;

  // Deallocate memory; the mock class should check for cleared data.
  e.deallocate(test_array, 4100);
  // 36864 bytes is the next highest size that is a multiple of the page size.
  EXPECT_EQ(e.GetErasedCount(), 36864);
}

TEST(SecureAllocator, SecureVectorIsClearedOnDestruction) {
  using TestSecureVector = std::vector<uint8_t, TestSecureAllocator<uint8_t>>;
  TestSecureAllocator<uint8_t> allocator;
  {
    TestSecureVector vector = {{1, 2, 3, 4}};
    EXPECT_EQ(vector.capacity(), 4);
  }
  // The allocator operates on page size blocks, so even though the vector's
  // capacity is 4, the actual amount of memory allocated is a page.
  // On destruction, each vector element is destroyed through
  // SecureAllocator::destroy, which clears the memory. Then the underlying
  // buffer (page in this case) is deallocated through
  // SecureAllocator::deallocate, which clears the memory.
  EXPECT_EQ(allocator.GetErasedCount(), 4 + 4096);
}

TEST(SecureAllocator, IsAlwaysEqualTrait) {
  EXPECT_EQ(SecureAllocator<uint8_t>::is_always_equal::value, true);
}

TEST(SecureAllocator, OperatorEqual) {
  SecureAllocator<uint8_t> allocator1;
  SecureAllocator<uint8_t> allocator2;
  EXPECT_TRUE(allocator1 == allocator2);
}

TEST(SecureAllocator, OperatorNotEqual) {
  SecureAllocator<uint8_t> allocator1;
  SecureAllocator<uint8_t> allocator2;
  // SecureAllocators should always be equal.
  EXPECT_FALSE(allocator1 != allocator2);
}

class SecureAllocatorMemlockTest : public ::testing::Test {
 public:
  static constexpr size_t kPageSize = 4096;

  SecureAllocatorMemlockTest() {
    struct rlimit limit;

    EXPECT_EQ(getrlimit(RLIMIT_MEMLOCK, &limit), 0);
    orig_limit_ = limit;

    // Using a page size value, since the allocator only allocates in
    // page-size chunks.
    limit.rlim_cur = kPageSize;
    EXPECT_LT(limit.rlim_cur, limit.rlim_max);
    EXPECT_EQ(setrlimit(RLIMIT_MEMLOCK, &limit), 0);

    EXPECT_EQ(getrlimit(RLIMIT_MEMLOCK, &limit), 0);
    EXPECT_EQ(limit.rlim_cur, kPageSize);
  }

  ~SecureAllocatorMemlockTest() override {
    // Restore original limits.
    EXPECT_EQ(setrlimit(RLIMIT_MEMLOCK, &orig_limit_), 0);
  }

 private:
  struct rlimit orig_limit_;
};

TEST_F(SecureAllocatorMemlockTest, MemlockLimitValid) {
  SecureAllocator<uint8_t> allocator;
  EXPECT_NE(allocator.allocate(kPageSize), nullptr);
}

// Test fails on ASAN build.
#if defined(BRILLO_ASAN_BUILD)
#define MAYBE_MemlockLimitDeathTest DISABLED_MemlockLimitDeathTest
#else
#define MAYBE_MemlockLimitDeathTest MemlockLimitDeathTest
#endif
TEST_F(SecureAllocatorMemlockTest, MAYBE_MemlockLimitDeathTest) {
  EXPECT_DEATH(
      {
        SecureAllocator<uint8_t> allocator;
        ASSERT_NE(allocator.allocate(kPageSize), nullptr);
        allocator.allocate(1);
      },
      "It is likely that SecureAllocator has exceeded the RLIMIT_MEMLOCK "
      "limit");
}

TEST(SecureVector, CopyAssignment) {
  SecureVector vector1 = {1, 2, 3, 4};
  SecureVector vector2 = {5, 6, 7, 8};
  EXPECT_NE(vector1, vector2);

  vector2 = vector1;
  EXPECT_EQ(vector1, vector2);
}

TEST(SecureVector, MoveAssignment) {
  SecureVector vector1 = {1, 2, 3, 4};
  SecureVector vector2 = {5, 6, 7, 8};
  EXPECT_NE(vector1, vector2);

  vector2 = std::move(vector1);
  EXPECT_EQ(vector2, SecureVector({1, 2, 3, 4}));
}

// DeathTests fork a new process and check how it proceeds. Take advantage
// of this and check if the value of SecureString is passed on to
// forked children.
#if GTEST_IS_THREADSAFE
// Check if the contents of the container are zeroed out.
void CheckPropagationOnFork(const brillo::SecureBlob& forked_blob,
                            const Blob& reference) {
  LOG(INFO) << forked_blob.to_string();
  for (int i = 0; i < forked_blob.size(); i++) {
    CHECK_NE(reference[i], forked_blob[i]);
    CHECK_EQ(forked_blob[i], 0);
  }
  exit(0);
}

TEST(SecureAllocatorDeathTest, ErasureOnFork) {
  Blob reference = BlobFromString("Test String");
  SecureBlob erasable_blob(reference.begin(), reference.end());

  EXPECT_EXIT(CheckPropagationOnFork(erasable_blob, reference),
              ::testing::ExitedWithCode(0), "");

  // In the original process, check the SecureBlob to see if it has not
  // changed.
  for (int i = 0; i < erasable_blob.size(); i++)
    EXPECT_EQ(erasable_blob[i], reference[i]);
}
#endif  // GTEST_IS_THREADSAFE

}  // namespace brillo
