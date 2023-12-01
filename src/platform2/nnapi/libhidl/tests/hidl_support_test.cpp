// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <android/hidl/memory/1.0/IMemory.h>
#include <android-base/logging.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <hidl/HidlSupport.h>
#include <hidl/Status.h>

#include <string>
#include <utility>
#include <vector>

// Unit tests for HidlSupport, taken from upstream. We do not want all
// of the upstream tests as we are not porting all of the classes from libhidl
// to work on Chrome OS, and upstream has all of the tests lumped into a single
// file src/aosp/system/libhidl/test_main.cpp.

#define EXPECT_ARRAYEQ(__a1__, __a2__, __size__) \
  EXPECT_TRUE(isArrayEqual(__a1__, __a2__, __size__))

#define EXPECT_2DARRAYEQ(__a1__, __a2__, __size1__, __size2__) \
  EXPECT_TRUE(is2dArrayEqual(__a1__, __a2__, __size1__, __size2__))

template <typename T, typename S>
static inline bool isArrayEqual(const T arr1, const S arr2, size_t size) {
  for (size_t i = 0; i < size; i++)
    if (arr1[i] != arr2[i])
      return false;
  return true;
}

template <typename T, typename S>
static inline bool is2dArrayEqual(const T arr1,
                                  const S arr2,
                                  size_t size1,
                                  size_t size2) {
  for (size_t i = 0; i < size1; i++)
    for (size_t j = 0; j < size2; j++)
      if (arr1[i][j] != arr2[i][j])
        return false;
  return true;
}

TEST(LibHidlTest, StringTest) {
  using android::hardware::hidl_string;
  hidl_string s;  // empty constructor
  EXPECT_STREQ(s.c_str(), "");
  hidl_string s1 = "s1";  // copy = from cstr
  EXPECT_STREQ(s1.c_str(), "s1");
  hidl_string s2("s2");  // copy constructor from cstr
  EXPECT_STREQ(s2.c_str(), "s2");
  hidl_string s2a(nullptr);  // copy constructor from null cstr
  EXPECT_STREQ("", s2a.c_str());
  s2a = nullptr;  // = from nullptr cstr
  EXPECT_STREQ(s2a.c_str(), "");
  hidl_string s3 = hidl_string("s3");  // move =
  EXPECT_STREQ(s3.c_str(), "s3");
  // copy constructor from cstr w/ length
  hidl_string s4 = hidl_string("12345", 3);
  EXPECT_STREQ(s4.c_str(), "123");
  hidl_string s5(hidl_string(hidl_string("s5")));  // move constructor
  EXPECT_STREQ(s5.c_str(), "s5");
  hidl_string s6(std::string("s6"));  // copy constructor from std::string
  EXPECT_STREQ(s6.c_str(), "s6");
  hidl_string s7 = std::string("s7");  // copy = from std::string
  EXPECT_STREQ(s7.c_str(), "s7");
  hidl_string s8(s7);  // copy constructor // NOLINT, test the copy ctor
  EXPECT_STREQ(s8.c_str(), "s7");
  hidl_string s9 = s8;  // copy =  // NOLINT, test the copy operator
  EXPECT_STREQ(s9.c_str(), "s7");
  char myCString[20] = "myCString";
  s.setToExternal(&myCString[0], strlen(myCString));
  EXPECT_STREQ(s.c_str(), "myCString");
  myCString[2] = 'D';
  EXPECT_STREQ(s.c_str(), "myDString");
  s.clear();  // should not affect myCString
  EXPECT_STREQ(myCString, "myDString");

  // casts
  s = "great";
  std::string myString = s;
  const char* anotherCString = s.c_str();
  EXPECT_EQ(myString, "great");
  EXPECT_STREQ(anotherCString, "great");

  const hidl_string t = "not so great";
  std::string myTString = t;
  const char* anotherTCString = t.c_str();
  EXPECT_EQ(myTString, "not so great");
  EXPECT_STREQ(anotherTCString, "not so great");

  // Assignment from hidl_string to std::string
  std::string tgt;
  hidl_string src("some stuff");
  tgt = src;
  EXPECT_STREQ(tgt.c_str(), "some stuff");

  // Stream output operator
  hidl_string msg("hidl_string works with operator<<");
  std::cout << msg;

  // Comparisons
  const char* cstr1 = "abc";
  std::string string1(cstr1);
  hidl_string hs1(cstr1);
  const char* cstrE = "abc";
  std::string stringE(cstrE);
  hidl_string hsE(cstrE);
  const char* cstrNE = "ABC";
  std::string stringNE(cstrNE);
  hidl_string hsNE(cstrNE);
  const char* cstr2 = "def";
  std::string string2(cstr2);
  hidl_string hs2(cstr2);

  EXPECT_TRUE(hs1 == hsE);
  EXPECT_FALSE(hs1 == hsNE);
  EXPECT_TRUE(hs1 == cstrE);
  EXPECT_FALSE(hs1 == cstrNE);
  EXPECT_TRUE(hs1 == stringE);
  EXPECT_FALSE(hs1 == stringNE);
  EXPECT_FALSE(hs1 != hsE);
  EXPECT_TRUE(hs1 != hsNE);
  EXPECT_FALSE(hs1 != cstrE);
  EXPECT_TRUE(hs1 != cstrNE);
  EXPECT_FALSE(hs1 != stringE);
  EXPECT_TRUE(hs1 != stringNE);

  EXPECT_TRUE(hs1 < hs2);
  EXPECT_FALSE(hs2 < hs1);
  EXPECT_TRUE(hs2 > hs1);
  EXPECT_FALSE(hs1 > hs2);
  EXPECT_TRUE(hs1 <= hs1);
  EXPECT_TRUE(hs1 <= hs2);
  EXPECT_FALSE(hs2 <= hs1);
  EXPECT_TRUE(hs1 >= hs1);
  EXPECT_TRUE(hs2 >= hs1);
  EXPECT_FALSE(hs2 <= hs1);
}

TEST(LibHidlTest, MemoryTest) {
  using android::hardware::hidl_memory;

  hidl_memory mem1 = hidl_memory();  // default constructor
  hidl_memory mem2 = mem1;           // copy constructor (nullptr), NOLINT

  EXPECT_EQ(nullptr, mem2.handle());

  native_handle_t* testHandle = native_handle_create(0, 0);

  hidl_memory mem3 = hidl_memory("foo", testHandle, 42);  // owns testHandle
  hidl_memory mem4 = mem3;  // copy constructor (regular handle), NOLINT

  EXPECT_EQ(mem3.name(), mem4.name());
  EXPECT_EQ(mem3.size(), mem4.size());
  EXPECT_NE(nullptr, mem4.handle());
  EXPECT_NE(mem3.handle(), mem4.handle());  // check handle cloned

  // hidl memory works with nullptr handle
  hidl_memory mem5 = hidl_memory("foo", nullptr, 0);
  hidl_memory mem6 = mem5;  // NOLINT, test copying
  EXPECT_EQ(nullptr, mem5.handle());
  EXPECT_EQ(nullptr, mem6.handle());

  native_handle_delete(testHandle);
}

TEST(LibHidlTest, VecInitTest) {
  using android::hardware::hidl_vec;
  using std::vector;
  int32_t array[] = {5, 6, 7};
  vector<int32_t> v(array, array + 3);

  hidl_vec<int32_t> hv0(3);    // size
  EXPECT_EQ(hv0.size(), 3ul);  // cannot say anything about its contents

  hidl_vec<int32_t> hv1 = v;  // copy =
  EXPECT_ARRAYEQ(hv1, array, 3);
  EXPECT_ARRAYEQ(hv1, v, 3);
  hidl_vec<int32_t> hv2(v);  // copy constructor
  EXPECT_ARRAYEQ(hv2, v, 3);

  vector<int32_t> v2 = hv1;  // cast
  EXPECT_ARRAYEQ(v2, v, 3);

  hidl_vec<int32_t> v3 = {5, 6, 7};  // initializer_list
  EXPECT_EQ(v3.size(), 3ul);
  EXPECT_ARRAYEQ(v3, array, v3.size());
}

TEST(LibHidlTest, VecReleaseTest) {
  // this test indicates an inconsistency of behaviors which is undesirable.
  // Perhaps hidl-vec should always allocate an empty vector whenever it
  // exposes its data. Alternatively, perhaps it should always free/reject
  // empty vectors and always return nullptr for this state. While this second
  // alternative is faster, it makes client code harder to write, and it would
  // break existing client code.
  using android::hardware::hidl_vec;

  hidl_vec<int32_t> empty;
  EXPECT_EQ(nullptr, empty.releaseData());

  empty.resize(0);
  int32_t* data = empty.releaseData();
  EXPECT_NE(nullptr, data);
  delete[] data;
}

TEST(LibHidlTest, VecIterTest) {
  int32_t array[] = {5, 6, 7};
  android::hardware::hidl_vec<int32_t> hv1 =
      std::vector<int32_t>(array, array + 3);

  auto iter = hv1.begin();  // iterator begin()
  EXPECT_EQ(*iter++, 5);
  EXPECT_EQ(*iter, 6);
  EXPECT_EQ(*++iter, 7);
  EXPECT_EQ(*iter--, 7);
  EXPECT_EQ(*iter, 6);
  EXPECT_EQ(*--iter, 5);

  iter += 2;
  EXPECT_EQ(*iter, 7);
  iter -= 2;
  EXPECT_EQ(*iter, 5);

  iter++;
  EXPECT_EQ(*(iter + 1), 7);
  EXPECT_EQ(*(1 + iter), 7);
  EXPECT_EQ(*(iter - 1), 5);
  EXPECT_EQ(*iter, 6);

  auto five = iter - 1;
  auto seven = iter + 1;
  EXPECT_EQ(seven - five, 2);
  EXPECT_EQ(five - seven, -2);

  EXPECT_LT(five, seven);
  EXPECT_LE(five, seven);
  EXPECT_GT(seven, five);
  EXPECT_GE(seven, five);

  EXPECT_EQ(seven[0], 7);
  EXPECT_EQ(five[1], 6);
}

TEST(LibHidlTest, VecIterForTest) {
  using android::hardware::hidl_vec;
  int32_t array[] = {5, 6, 7};
  hidl_vec<int32_t> hv1 = std::vector<int32_t>(array, array + 3);

  int32_t sum = 0;  // range based for loop interoperability
  for (auto&& i : hv1) {
    sum += i;
  }
  EXPECT_EQ(sum, 5 + 6 + 7);

  for (auto iter = hv1.begin(); iter < hv1.end(); ++iter) {
    *iter += 10;
  }
  const hidl_vec<int32_t>& v4 = hv1;
  sum = 0;
  for (const auto& i : v4) {
    sum += i;
  }
  EXPECT_EQ(sum, 15 + 16 + 17);
}

TEST(LibHidlTest, VecEqTest) {
  android::hardware::hidl_vec<int32_t> hv1{5, 6, 7};
  android::hardware::hidl_vec<int32_t> hv2{5, 6, 7};
  android::hardware::hidl_vec<int32_t> hv3{5, 6, 8};

  // use the == and != operator intentionally here
  EXPECT_TRUE(hv1 == hv2);
  EXPECT_TRUE(hv1 != hv3);
}

TEST(LibHidlTest, VecEqInitializerTest) {
  std::vector<int32_t> reference{5, 6, 7};
  android::hardware::hidl_vec<int32_t> hv1{1, 2, 3};
  hv1 = {5, 6, 7};
  android::hardware::hidl_vec<int32_t> hv2;
  hv2 = {5, 6, 7};
  android::hardware::hidl_vec<int32_t> hv3;
  hv3 = {5, 6, 8};

  // use the == and != operator intentionally here
  EXPECT_TRUE(hv1 == hv2);
  EXPECT_TRUE(hv1 == reference);
  EXPECT_TRUE(hv1 != hv3);
}

TEST(LibHidlTest, VecRangeCtorTest) {
  struct ConvertibleType {
    int val;

    explicit ConvertibleType(int val) : val(val) {}
    explicit operator int() const { return val; }
    bool operator==(const int& other) const { return val == other; }
  };

  std::vector<ConvertibleType> input{
      ConvertibleType(1),
      ConvertibleType(2),
      ConvertibleType(3),
  };

  android::hardware::hidl_vec<int> hv(input.begin(), input.end());

  EXPECT_EQ(input.size(), hv.size());
  int sum = 0;
  for (unsigned i = 0; i < input.size(); i++) {
    EXPECT_EQ(input[i], hv[i]);
    sum += hv[i];
  }
  EXPECT_EQ(sum, 1 + 2 + 3);
}

struct FailsIfCopied {
  FailsIfCopied() {}

  // add failure if copied since in general this can be expensive
  FailsIfCopied(const FailsIfCopied& o) { *this = o; }
  FailsIfCopied& operator=(const FailsIfCopied&) {
    ADD_FAILURE() << "FailsIfCopied copied";
    return *this;
  }

  // fine to move this type since in general this is cheaper
  FailsIfCopied(FailsIfCopied&& o) = default;
  FailsIfCopied& operator=(FailsIfCopied&&) = default;
};

TEST(LibHidlTest, VecResizeNoCopy) {
  using android::hardware::hidl_vec;

  hidl_vec<FailsIfCopied> noCopies;
  noCopies.resize(3);  // instantiates three elements

  FailsIfCopied* oldPointer = noCopies.data();

  noCopies.resize(6);  // should move three elements, not copy

  // oldPointer should be invalidated at this point.
  // hidl_vec doesn't currently try to realloc but if it ever switches
  // to an implementation that does, this test wouldn't do anything.
  EXPECT_NE(oldPointer, noCopies.data());
}

TEST(LibHidlTest, VecFindTest) {
  using android::hardware::hidl_vec;
  hidl_vec<int32_t> hv1 = {10, 20, 30, 40};
  const hidl_vec<int32_t> hv2 = {1, 2, 3, 4};

  auto it = hv1.find(20);
  EXPECT_EQ(20, *it);
  *it = 21;
  EXPECT_EQ(21, *it);
  it = hv1.find(20);
  EXPECT_EQ(hv1.end(), it);
  it = hv1.find(21);
  EXPECT_EQ(21, *it);

  auto cit = hv2.find(4);
  EXPECT_EQ(4, *cit);
}

TEST(LibHidlTest, VecContainsTest) {
  using android::hardware::hidl_vec;
  hidl_vec<int32_t> hv1 = {10, 20, 30, 40};
  const hidl_vec<int32_t> hv2 = {0, 1, 2, 3, 4};

  EXPECT_TRUE(hv1.contains(10));
  EXPECT_TRUE(hv1.contains(40));
  EXPECT_FALSE(hv1.contains(1));
  EXPECT_FALSE(hv1.contains(0));
  EXPECT_TRUE(hv2.contains(0));
  EXPECT_FALSE(hv2.contains(10));

  hv1[0] = 11;
  EXPECT_FALSE(hv1.contains(10));
  EXPECT_TRUE(hv1.contains(11));
}

TEST(LibHidlTest, ArrayTest) {
  using android::hardware::hidl_array;
  int32_t array[] = {5, 6, 7};

  hidl_array<int32_t, 3> ha(array);
  EXPECT_ARRAYEQ(ha, array, 3);
}

TEST(LibHidlTest, StringCmpTest) {
  using android::hardware::hidl_string;
  const char* s = "good";
  hidl_string hs(s);
  EXPECT_NE(hs.c_str(), s);

  EXPECT_TRUE(hs == s);  // operator ==
  EXPECT_TRUE(s == hs);

  EXPECT_FALSE(hs != s);  // operator ==
  EXPECT_FALSE(s != hs);
}

template <typename T>
void great(android::hardware::hidl_vec<T>) {}

TEST(LibHidlTest, VecCopyTest) {
  android::hardware::hidl_vec<int32_t> v;
  great(v);
}

TEST(LibHidlTest, StdArrayTest) {
  using android::hardware::hidl_array;
  hidl_array<int32_t, 5> array{(int32_t[5]){1, 2, 3, 4, 5}};
  std::array<int32_t, 5> stdArray = array;
  EXPECT_ARRAYEQ(array.data(), stdArray.data(), 5);
  hidl_array<int32_t, 5> array2 = stdArray;
  EXPECT_ARRAYEQ(array.data(), array2.data(), 5);
}

TEST(LibHidlTest, MultiDimStdArrayTest) {
  using android::hardware::hidl_array;
  hidl_array<int32_t, 2, 3> array;
  for (size_t i = 0; i < 2; i++) {
    for (size_t j = 0; j < 3; j++) {
      array[i][j] = i + j + i * j;
    }
  }
  std::array<std::array<int32_t, 3>, 2> stdArray = array;
  EXPECT_2DARRAYEQ(array, stdArray, 2, 3);
  hidl_array<int32_t, 2, 3> array2 = stdArray;
  EXPECT_2DARRAYEQ(array, array2, 2, 3);
}

TEST(LibHidlTest, HidlVersionTest) {
  using android::hardware::hidl_version;
  hidl_version v1_0{1, 0};
  EXPECT_EQ(1, v1_0.get_major());
  EXPECT_EQ(0, v1_0.get_minor());
  hidl_version v2_0{2, 0};
  hidl_version v2_1{2, 1};
  hidl_version v2_2{2, 2};
  hidl_version v3_0{3, 0};
  hidl_version v3_0b{3, 0};

  EXPECT_TRUE(v1_0 < v2_0);
  EXPECT_TRUE(v1_0 != v2_0);
  EXPECT_TRUE(v2_0 < v2_1);
  EXPECT_TRUE(v2_1 < v3_0);
  EXPECT_TRUE(v2_0 > v1_0);
  EXPECT_TRUE(v2_0 != v1_0);
  EXPECT_TRUE(v2_1 > v2_0);
  EXPECT_TRUE(v3_0 > v2_1);
  EXPECT_TRUE(v3_0 == v3_0b);
  EXPECT_FALSE(v3_0 != v3_0b);
  EXPECT_TRUE(v3_0 <= v3_0b);
  EXPECT_TRUE(v2_2 <= v3_0);
  EXPECT_TRUE(v3_0 >= v3_0b);
  EXPECT_TRUE(v3_0 >= v2_2);
}

TEST(LibHidlTest, ReturnMoveTest) {
  using ::android::DEAD_OBJECT;
  using ::android::hardware::Return;
  using ::android::hardware::Status;
  Return<void> ret{Status::fromStatusT(DEAD_OBJECT)};
  ret.isOk();
  ret = {Status::fromStatusT(DEAD_OBJECT)};
  ret.isOk();
}

TEST(LibHidlTest, ReturnTest) {
  using ::android::DEAD_OBJECT;
  using ::android::hardware::hidl_string;
  using ::android::hardware::Return;
  using ::android::hardware::Status;

  EXPECT_FALSE(Return<void>(Status::fromStatusT(DEAD_OBJECT)).isOk());
  EXPECT_TRUE(Return<void>(Status::ok()).isOk());

  hidl_string one = "1";
  hidl_string two = "2";
  Return<hidl_string> ret =
      Return<hidl_string>(Status::fromStatusT(DEAD_OBJECT));

  EXPECT_EQ(one, Return<hidl_string>(one).withDefault(two));
  EXPECT_EQ(two, ret.withDefault(two));

  hidl_string&& moved = ret.withDefault(std::move(two));
  EXPECT_EQ("2", moved);

  const hidl_string three = "3";
  EXPECT_EQ(three, ret.withDefault(three));
}

TEST(LibHidlTest, ReturnDies) {
  using ::android::hardware::Return;
  using ::android::hardware::Status;

  EXPECT_DEATH({ Return<void>(Status::fromStatusT(-EBUSY)); }, "");
  EXPECT_DEATH({ Return<void>(Status::fromStatusT(-EBUSY)).isDeadObject(); },
               "");
  EXPECT_DEATH(
      {
        Return<int> ret = Return<int>(Status::fromStatusT(-EBUSY));
        int foo = ret;  // should crash here
        (void)foo;
        ret.isOk();
      },
      "");
}

TEST(LibHidlTest, DetectUncheckedReturn) {
  using ::android::hardware::HidlReturnRestriction;
  using ::android::hardware::Return;
  using ::android::hardware::setProcessHidlReturnRestriction;
  using ::android::hardware::Status;

  setProcessHidlReturnRestriction(HidlReturnRestriction::FATAL_IF_UNCHECKED);

  EXPECT_DEATH(
      {
        auto ret = Return<void>(Status::ok());
        (void)ret;
      },
      "");
  EXPECT_DEATH(
      {
        auto ret = Return<void>(Status::ok());
        ret = Return<void>(Status::ok());
        ret.isOk();
      },
      "");

  auto ret = Return<void>(Status::ok());
  (void)ret.isOk();
  ret = Return<void>(Status::ok());
  (void)ret.isOk();

  setProcessHidlReturnRestriction(HidlReturnRestriction::NONE);
}

std::string toString(const ::android::hardware::Status& s) {
  using ::android::hardware::operator<<;
  std::ostringstream oss;
  oss << s;
  return oss.str();
}

TEST(LibHidlTest, StatusStringTest) {
  using ::android::DEAD_OBJECT;
  using ::android::hardware::Status;
  using ::testing::HasSubstr;

  EXPECT_EQ(toString(Status::ok()), "No error");

  EXPECT_THAT(toString(Status::fromStatusT(DEAD_OBJECT)),
              HasSubstr("DEAD_OBJECT"));

  EXPECT_THAT(toString(Status::fromStatusT(-EBUSY)), HasSubstr("busy"));

  EXPECT_THAT(toString(Status::fromExceptionCode(Status::EX_NULL_POINTER)),
              HasSubstr("EX_NULL_POINTER"));
}
