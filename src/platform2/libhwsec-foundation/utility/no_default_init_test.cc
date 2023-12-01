// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <memory>
#include <string>
#include <variant>
#include <vector>

#include <base/check.h>
#include <base/logging.h>
#include <brillo/secure_blob.h>

#include <gtest/gtest.h>

#include "libhwsec-foundation/utility/no_default_init.h"

namespace hwsec_foundation {

namespace {

TEST(NoDefaultInitTest, StdString) {
  NoDefault<std::string> empty("");
  NoDefault<std::string> str1("Hello");
  NoDefault<std::string> str2("World");
  NoDefault<std::string> str3 = str1;
  NoDefault<std::string> str4(str2);

  EXPECT_TRUE(empty.empty());
  EXPECT_FALSE(str1.empty());
  EXPECT_FALSE(str2.empty());
  EXPECT_FALSE(str3.empty());
  EXPECT_FALSE(str4.empty());

  EXPECT_NE(str1, str2);
  EXPECT_EQ(str1, str3);
  EXPECT_EQ(str2, str4);

  EXPECT_EQ(str1, "Hello");
  EXPECT_EQ(str2, "World");
  EXPECT_NE(str1, "Greetings");

  EXPECT_EQ(str1.substr(3), "lo");
  EXPECT_EQ(str1 + " " + str2, "Hello World");

  str1 += " HWSEC";
  EXPECT_EQ(str1, "Hello HWSEC");

  auto uni_str = std::make_unique<std::string>(str1);
  EXPECT_EQ(*uni_str, "Hello HWSEC");
}

TEST(NoDefaultInitTest, BrilloBlobs) {
  NoDefault<brillo::Blob> blob = brillo::BlobFromString("blob");
  NoDefault<brillo::SecureBlob> secure_blob("secure_blob");
  NoDefault<brillo::Blob> blob2{'b', 'l', 'o', 'b'};

  EXPECT_FALSE(blob.empty());
  EXPECT_FALSE(secure_blob.empty());

  EXPECT_EQ(brillo::BlobToString(blob), "blob");
  EXPECT_EQ(brillo::BlobToString(blob), brillo::BlobToString(blob2));
  EXPECT_EQ(secure_blob.to_string(), "secure_blob");

  int i = 0;
  for (uint8_t data : blob) {
    EXPECT_EQ(data, blob[i++]);
  }

  i = 0;
  for (uint8_t data : secure_blob) {
    EXPECT_EQ(data, secure_blob[i++]);
  }

  secure_blob = brillo::SecureBlob(blob);
  EXPECT_EQ(secure_blob.to_string(), brillo::BlobToString(blob));
}

TEST(NoDefaultInitTest, UniquePtr) {
  NoDefault<std::unique_ptr<int>> ptr1 = std::make_unique<int>(1234);
  NoDefault<std::unique_ptr<int>> ptr2 = nullptr;

  ASSERT_NE(ptr1, nullptr);
  EXPECT_EQ(ptr2, nullptr);

  EXPECT_EQ(*ptr1, 1234);

  ptr2 = std::move(static_cast<std::unique_ptr<int>&>(ptr1));

  EXPECT_EQ(ptr1, nullptr);
  ASSERT_NE(ptr2, nullptr);

  EXPECT_EQ(*ptr2, 1234);
}

TEST(NoDefaultInitTest, Int) {
  NoDefault<int> val1 = 1234;
  NoDefault<uint8_t> val2 = 123;
  NoDefault<uint16_t> val3 = 12345;
  NoDefault<uint32_t> val4 = 12345678;
  NoDefault<uint64_t> val5 = 123456789012345ULL;

  EXPECT_EQ(val1, 1234);
  EXPECT_EQ(val2, 123);
  EXPECT_EQ(val3, 12345);
  EXPECT_EQ(val4, 12345678);
  EXPECT_EQ(val5, 123456789012345ULL);

  EXPECT_NE(val2, val1);
  EXPECT_NE(val3, val1);
  EXPECT_NE(val4, val1);
  EXPECT_NE(val5, val1);

  val3 = static_cast<int>(val1);
  val4 = static_cast<int>(val1);
  val5 = static_cast<int>(val1);

  EXPECT_EQ(val3, 1234);
  EXPECT_EQ(val4, 1234);
  EXPECT_EQ(val5, 1234);

  EXPECT_EQ(val3, val1);
  EXPECT_EQ(val4, val1);
  EXPECT_EQ(val5, val1);

  val1 = 567;
  EXPECT_EQ(val1, 567);

  EXPECT_EQ(val1 + 321, 888);
  val1 += 321;
  EXPECT_EQ(val1, 888);

  EXPECT_EQ(val1 - 111, 777);
  val1 -= 111;
  EXPECT_EQ(val1, 777);

  EXPECT_EQ(val1 / 7, 111);
  val1 /= 7;
  EXPECT_EQ(val1, 111);

  val1 = val1 + 10;
  EXPECT_EQ(val1, 121);

  EXPECT_EQ(val1 % 11, 0);
  val1 %= 11;
  EXPECT_EQ(val1, 0);

  EXPECT_EQ(val1++, 0);
  EXPECT_EQ(val1, 1);

  EXPECT_EQ(++val1, 2);
  EXPECT_EQ(val1, 2);

  EXPECT_EQ(--val1, 1);
  EXPECT_EQ(val1, 1);

  EXPECT_EQ(val1--, 1);
  EXPECT_EQ(val1, 0);

  EXPECT_EQ(val1 ^ 1, 1);
  val1 ^= 1;
  EXPECT_EQ(val1, 1);

  EXPECT_EQ(val1 << 10, 1024);
  val1 <<= 10;
  EXPECT_EQ(val1, 1024);

  EXPECT_EQ(val1 >> 4, 64);
  val1 >>= 4;
  EXPECT_EQ(val1, 64);

  EXPECT_EQ(val1 | 4, 68);
  val1 |= 4;
  EXPECT_EQ(val1, 68);

  EXPECT_EQ(val1 & 4, 4);
  val1 &= 4;
  EXPECT_EQ(val1, 4);

  val1 = 0;
  EXPECT_EQ(val1, 0);

  EXPECT_EQ(~val1, -1);
  val1 = ~val1;
  EXPECT_EQ(val1, -1);
}

TEST(NoDefaultInitTest, Double) {
  NoDefault<double> val1 = 1234.5;

  EXPECT_EQ(val1, 1234.5);

  NoDefault<int> val2 = static_cast<double>(val1);

  EXPECT_EQ(val2, 1234);
}

TEST(NoDefaultInitTest, IntPointer) {
  auto uni_ptr = std::make_unique<int>(567);
  NoDefault<int*> ptr = uni_ptr.get();

  EXPECT_EQ(*ptr, 567);

  *ptr += 321;
  EXPECT_EQ(*ptr, 888);
}

TEST(NoDefaultInitTest, StringPointer) {
  auto uni_ptr = std::make_unique<std::string>("magic");
  NoDefault<std::string*> ptr = uni_ptr.get();

  EXPECT_EQ(*ptr, "magic");

  EXPECT_EQ(ptr->substr(3), "ic");

  *ptr = "Hello, world";

  EXPECT_EQ(*ptr, "Hello, world");

  EXPECT_EQ(ptr->substr(7), "world");
  EXPECT_EQ((*ptr).substr(7), "world");

  ptr->erase(5);
  EXPECT_EQ(*ptr, "Hello");

  (*ptr).erase(3);
  EXPECT_EQ(*ptr, "Hel");
}

TEST(NoDefaultInitTest, Struct) {
  struct TestStruct {
    NoDefault<int> val;
    NoDefault<std::string> str;
  };

  struct TestStruct2 {
    NoDefault<TestStruct> inner1;
    NoDefault<TestStruct> inner2;
  };

  // TestStruct inner_data; // This would not work.
  // TestStruct2 data; // This would not work.

  TestStruct data1{
      .val = 123,
      .str = "magic",
  };

  NoDefault<TestStruct> data2({
      .val = 123,
      .str = "magic",
  });

  EXPECT_EQ(data1.val, data2.val);
  EXPECT_EQ(data1.str, data2.str);

  TestStruct2 data3{
      .inner1 =
          TestStruct{
              .val = 567,
              .str = "hello",
          },
      .inner2 =
          TestStruct{
              .val = 789,
              .str = "world",
          },
  };
  EXPECT_EQ(data3.inner1.val, 567);
  EXPECT_EQ(data3.inner1.str, "hello");
  EXPECT_EQ(data3.inner2.val, 789);
  EXPECT_EQ(data3.inner2.str, "world");
}

TEST(NoDefaultInitTest, Union) {
  union TestUnion {
    NoDefault<int> val_int;
    NoDefault<double> val_double;
  };

  // TestUnion data; // This would not work.
  TestUnion data1{.val_int = 123};
  TestUnion data2{.val_double = 5566.7};

  EXPECT_EQ(data1.val_int, 123);
  EXPECT_EQ(data2.val_double, 5566.7);
}

TEST(NoDefaultInitTest, Variant) {
  using TestVariant = NoDefault<std::variant<int, std::string>>;

  // TestVariant data; // This would not work.
  TestVariant data1 = 123;
  TestVariant data2 = "string_data";

  ASSERT_TRUE(std::holds_alternative<int>(data1));
  ASSERT_TRUE(std::holds_alternative<std::string>(data2));
  EXPECT_EQ(std::get<int>(data1), 123);
  EXPECT_EQ(std::get<std::string>(data2), "string_data");
}

TEST(NoDefaultInitTest, ConstexprInt) {
  constexpr NoDefault<int> x = 123;
  EXPECT_EQ(x, 123);
  static constexpr int y = 5678;
  constexpr NoDefault<const int*> z = &y;
  EXPECT_EQ(*z, 5678);
}

TEST(NoDefaultInitTest, ConstexprChar) {
  static constexpr char x[] = "abcdefg";
  constexpr NoDefault<const char*> y = x;
  EXPECT_EQ(std::string(x), std::string(y));
}

TEST(NoDefaultInitTest, ConstexprFunc) {
  struct SortedElement {
    int id;
    const char* name;
  };

  static constexpr NoDefault<SortedElement> kSortedElements[] = {
      SortedElement{.id = 1, .name = "nameA"},
      SortedElement{.id = 3, .name = "nameB"},
      SortedElement{.id = 6, .name = "nameC"},
      SortedElement{.id = 8, .name = "nameD"},
      SortedElement{.id = 9, .name = "nameE"},
      SortedElement{.id = 10, .name = "nameF"},
      SortedElement{.id = 123, .name = "nameG"},
      SortedElement{.id = 456, .name = "nameH"},
  };

  constexpr auto IsListSorted = []() -> bool {
    SortedElement prev = {.id = -1, .name = ""};
    for (const auto& p : kSortedElements) {
      if (p.id < prev.id) {
        return false;
      }
    }
    return true;
  };

  static_assert(IsListSorted(), "kSortedElements is not sorted.");

  static constexpr NoDefault<int> kSortedElements2[] = {1, 3, 5, 7, 9, 10};

  constexpr auto IsListSorted2 = []() -> bool {
    int prev = -1;
    for (int p : kSortedElements2) {
      if (p < prev) {
        return false;
      }
    }
    return true;
  };

  static_assert(IsListSorted2(), "kSortedElements2 is not sorted.");
}

}  // namespace

}  // namespace hwsec_foundation
