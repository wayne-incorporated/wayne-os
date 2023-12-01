// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/store/key_file_store.h"

#include <sys/stat.h>

#include <limits>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <base/containers/contains.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>
#include <inttypes.h>

#include "shill/data_types.h"
#include "shill/store/key_value_store.h"
#include "shill/store/pkcs11_slot_getter.h"

using testing::Test;

namespace shill {

class KeyFileStoreTest : public Test {
 public:
  KeyFileStoreTest() = default;

  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    test_file_ = temp_dir_.GetPath().Append("test-key-file-store");
    slot_getter_ = std::make_unique<Pkcs11SlotGetter>(/*user_hash=*/"");
    store_ = std::make_unique<KeyFileStore>(test_file_, slot_getter_.get());
  }

  void TearDown() override { ASSERT_TRUE(temp_dir_.Delete()); }

 protected:
  std::string ReadKeyFile();
  void WriteKeyFile(std::string data);

  base::ScopedTempDir temp_dir_;
  base::FilePath test_file_;
  std::unique_ptr<Pkcs11SlotGetter> slot_getter_;
  std::unique_ptr<KeyFileStore> store_;
};

std::string KeyFileStoreTest::ReadKeyFile() {
  std::string data;
  EXPECT_TRUE(base::ReadFileToString(test_file_, &data));
  return data;
}

void KeyFileStoreTest::WriteKeyFile(std::string data) {
  EXPECT_EQ(data.size(), base::WriteFile(test_file_, data.data(), data.size()));
}

TEST_F(KeyFileStoreTest, OpenClose) {
  EXPECT_FALSE(store_->key_file_);

  EXPECT_TRUE(store_->IsEmpty());
  ASSERT_TRUE(store_->Open());
  EXPECT_TRUE(store_->key_file_);
  ASSERT_TRUE(store_->Close());
  EXPECT_FALSE(store_->key_file_);
  base::FileEnumerator file_enumerator(temp_dir_.GetPath(),
                                       false /* not recursive */,
                                       base::FileEnumerator::FILES);

  // Verify that the file actually got written with the right name.
  EXPECT_EQ(test_file_.value(), file_enumerator.Next().value());
  const auto file_info = file_enumerator.GetInfo();

  // Verify that the profile is a regular file, readable and writeable by the
  // owner only.
  EXPECT_EQ(S_IFREG | S_IRUSR | S_IWUSR, file_info.stat().st_mode);

  ASSERT_TRUE(store_->Open());
  EXPECT_TRUE(store_->key_file_);
  ASSERT_TRUE(store_->Close());
  EXPECT_FALSE(store_->key_file_);

  ASSERT_TRUE(store_->Open());
  // Replace file with directory, to force Flush() to fail.
  ASSERT_TRUE(base::DeleteFile(test_file_));
  ASSERT_TRUE(base::CreateDirectory(test_file_));
  ASSERT_FALSE(store_->Close());
  EXPECT_FALSE(store_->key_file_);
}

TEST_F(KeyFileStoreTest, OpenFail) {
  WriteKeyFile("garbage\n");
  EXPECT_FALSE(store_->Open());
  EXPECT_FALSE(store_->key_file_);
}

TEST_F(KeyFileStoreTest, MarkAsCorrupted) {
  EXPECT_FALSE(store_->MarkAsCorrupted());
  EXPECT_TRUE(store_->IsEmpty());
  WriteKeyFile("garbage\n");
  EXPECT_FALSE(store_->IsEmpty());
  EXPECT_TRUE(base::PathExists(test_file_));
  EXPECT_TRUE(store_->MarkAsCorrupted());
  EXPECT_TRUE(store_->IsEmpty());
  EXPECT_FALSE(base::PathExists(test_file_));
  EXPECT_TRUE(
      base::PathExists(base::FilePath(test_file_.value() + ".corrupted")));
}

TEST_F(KeyFileStoreTest, GetGroups) {
  static const char kGroupA[] = "g-a";
  static const char kGroupB[] = "g-b";
  static const char kGroupC[] = "g-c";
  WriteKeyFile(
      base::StringPrintf("[%s]\n"
                         "[%s]\n"
                         "[%s]\n",
                         kGroupA, kGroupB, kGroupC));
  EXPECT_FALSE(store_->IsEmpty());
  ASSERT_TRUE(store_->Open());
  std::set<std::string> groups = store_->GetGroups();
  EXPECT_EQ(3, groups.size());
  EXPECT_TRUE(base::Contains(groups, kGroupA));
  EXPECT_TRUE(base::Contains(groups, kGroupB));
  EXPECT_TRUE(base::Contains(groups, kGroupC));
  EXPECT_FALSE(base::Contains(groups, "g-x"));
  ASSERT_TRUE(store_->Close());
}

TEST_F(KeyFileStoreTest, GetGroupsWithKey) {
  static const char kGroupA[] = "g-a";
  static const char kGroupB[] = "g-b";
  static const char kGroupC[] = "g-c";
  static const char kKeyA[] = "k-a";
  static const char kKeyB[] = "k-b";
  static const char kValue[] = "true";
  WriteKeyFile(
      base::StringPrintf("[%s]\n"
                         "%s=%s\n"
                         "[%s]\n"
                         "%s=%s\n"
                         "%s=%s\n"
                         "[%s]\n"
                         "%s=%s\n",
                         kGroupA, kKeyA, kValue, kGroupB, kKeyA, kValue, kKeyB,
                         kValue, kGroupC, kKeyB, kValue));
  EXPECT_FALSE(store_->IsEmpty());
  ASSERT_TRUE(store_->Open());
  std::set<std::string> groups_a = store_->GetGroupsWithKey(kKeyA);
  EXPECT_EQ(2, groups_a.size());
  EXPECT_TRUE(base::Contains(groups_a, kGroupA));
  EXPECT_TRUE(base::Contains(groups_a, kGroupB));
  std::set<std::string> groups_b = store_->GetGroupsWithKey(kKeyB);
  EXPECT_EQ(2, groups_b.size());
  EXPECT_TRUE(base::Contains(groups_b, kGroupB));
  EXPECT_TRUE(base::Contains(groups_b, kGroupC));
  ASSERT_TRUE(store_->Close());
}

TEST_F(KeyFileStoreTest, ContainsGroup) {
  static const char kGroupA[] = "group-a";
  static const char kGroupB[] = "group-b";
  static const char kGroupC[] = "group-c";
  WriteKeyFile(
      base::StringPrintf("[%s]\n"
                         "[%s]\n"
                         "[%s]\n",
                         kGroupA, kGroupB, kGroupC));
  ASSERT_TRUE(store_->Open());
  EXPECT_TRUE(store_->ContainsGroup(kGroupA));
  EXPECT_TRUE(store_->ContainsGroup(kGroupB));
  EXPECT_TRUE(store_->ContainsGroup(kGroupC));
  EXPECT_FALSE(store_->ContainsGroup("group-d"));
  ASSERT_TRUE(store_->Close());
}

TEST_F(KeyFileStoreTest, GetGroupsWithProperties) {
  static const char kGroupA[] = "group-a";
  static const char kGroupB[] = "group-b";
  static const char kGroupC[] = "group-c";
  static const char kAttributeA[] = "attr-a";
  static const char kAttributeB[] = "attr-b";
  static const char kAttributeC[] = "attr-c";
  static const char kValueA_0[] = "val-a";
  static const char kValueA_1[] = "val-b";
  static const int kValueB_0 = 1;
  static const int kValueB_1 = 2;
  static const bool kValueC_0 = true;
  static const char kValueC_0_string[] = "true";
  static const bool kValueC_1 = false;
  static const char kValueC_1_string[] = "false";
  WriteKeyFile(base::StringPrintf(
      "[%s]\n"
      "%s=%s\n"
      "%s=%d\n"
      "%s=%s\n"
      "[%s]\n"
      "%s=%s\n"
      "%s=%d\n"
      "%s=%s\n"
      "[%s]\n"
      "%s=%s\n"
      "%s=%d\n"
      "%s=%s\n",
      kGroupA, kAttributeA, kValueA_0, kAttributeB, kValueB_0, kAttributeC,
      kValueC_0_string, kGroupB, kAttributeA, kValueA_0, kAttributeB, kValueB_1,
      kAttributeC, kValueC_0_string, kGroupC, kAttributeA, kValueA_0,
      kAttributeB, kValueB_0, kAttributeC, kValueC_1_string));
  ASSERT_TRUE(store_->Open());
  {
    KeyValueStore args;
    args.Set<std::string>(kAttributeA, kValueA_0);
    args.Set<int32_t>(kAttributeB, kValueB_0);
    std::set<std::string> results = store_->GetGroupsWithProperties(args);
    EXPECT_EQ(2, results.size());
    EXPECT_TRUE(results.find(kGroupA) != results.end());
    EXPECT_TRUE(results.find(kGroupC) != results.end());
  }
  {
    KeyValueStore args;
    args.Set<std::string>(kAttributeA, kValueA_0);
    args.Set<bool>(kAttributeC, kValueC_0);
    std::set<std::string> results = store_->GetGroupsWithProperties(args);
    EXPECT_EQ(2, results.size());
    EXPECT_TRUE(results.find(kGroupA) != results.end());
    EXPECT_TRUE(results.find(kGroupB) != results.end());
  }
  {
    KeyValueStore args;
    args.Set<bool>(kAttributeC, kValueC_1);
    std::set<std::string> results = store_->GetGroupsWithProperties(args);
    EXPECT_EQ(1, results.size());
    EXPECT_TRUE(results.find(kGroupC) != results.end());
  }
  {
    KeyValueStore args;
    args.Set<std::string>(kAttributeA, kValueA_0);
    std::set<std::string> results = store_->GetGroupsWithProperties(args);
    EXPECT_EQ(3, results.size());
    EXPECT_TRUE(results.find(kGroupA) != results.end());
    EXPECT_TRUE(results.find(kGroupB) != results.end());
    EXPECT_TRUE(results.find(kGroupC) != results.end());
  }
  {
    KeyValueStore args;
    args.Set<std::string>(kAttributeA, kValueA_1);
    std::set<std::string> results = store_->GetGroupsWithProperties(args);
    EXPECT_EQ(0, results.size());
  }
  ASSERT_TRUE(store_->Close());
}

TEST_F(KeyFileStoreTest, DeleteKey) {
  static const char kGroup[] = "the-group";
  static const char kKeyDead[] = "dead";
  static const char kKeyAlive[] = "alive";
  const int kValueAlive = 3;
  WriteKeyFile(
      base::StringPrintf("[%s]\n"
                         "%s=5\n"
                         "%s=%d\n",
                         kGroup, kKeyDead, kKeyAlive, kValueAlive));
  ASSERT_TRUE(store_->Open());
  EXPECT_TRUE(store_->DeleteKey(kGroup, kKeyDead));
  EXPECT_FALSE(store_->DeleteKey(kGroup, "random-key"));
  EXPECT_FALSE(store_->DeleteKey("random-group", kKeyAlive));
  ASSERT_TRUE(store_->Close());
  EXPECT_EQ(base::StringPrintf("[%s]\n"
                               "%s=%d\n",
                               kGroup, kKeyAlive, kValueAlive),
            ReadKeyFile());
}

TEST_F(KeyFileStoreTest, DeleteGroup) {
  static const char kGroupA[] = "group-a";
  static const char kGroupB[] = "group-b";
  static const char kGroupC[] = "group-c";
  WriteKeyFile(
      base::StringPrintf("[%s]\n"
                         "[%s]\n"
                         "key-to-be-deleted=true\n"
                         "[%s]\n",
                         kGroupA, kGroupB, kGroupC));
  ASSERT_TRUE(store_->Open());
  EXPECT_TRUE(store_->DeleteGroup(kGroupB));
  EXPECT_FALSE(store_->DeleteGroup("group-d"));
  ASSERT_TRUE(store_->Close());
  EXPECT_EQ(base::StringPrintf("[%s]\n"
                               "\n"
                               "[%s]\n",
                               kGroupA, kGroupC),
            ReadKeyFile());
}

TEST_F(KeyFileStoreTest, RetainLeadingWhitespaceInCommentLine) {
  static const char kGroup[] = "the-group";
  static const char kCommentLine[] = "     # comment line";
  static const char kKeyAlive[] = "alive";
  const int kValueAlive = 3;
  WriteKeyFile(
      base::StringPrintf("[%s]\n"
                         "%s\n"
                         "%s=%d\n",
                         kGroup, kCommentLine, kKeyAlive, kValueAlive));
  ASSERT_TRUE(store_->Open());
  ASSERT_TRUE(store_->Close());
  EXPECT_EQ(base::StringPrintf("[%s]\n"
                               "%s\n"
                               "%s=%d\n",
                               kGroup, kCommentLine, kKeyAlive, kValueAlive),
            ReadKeyFile());
}

TEST_F(KeyFileStoreTest, TrimWhitespaceBeforeGroupHeader) {
  static const char kGroup[] = "the-group";
  static const char kKeyAlive[] = "alive";
  const int kValueAlive = 3;
  WriteKeyFile(
      base::StringPrintf("    [%s]\n"
                         "%s=%d\n",
                         kGroup, kKeyAlive, kValueAlive));
  ASSERT_TRUE(store_->Open());
  ASSERT_TRUE(store_->Close());
  EXPECT_EQ(base::StringPrintf("[%s]\n"
                               "%s=%d\n",
                               kGroup, kKeyAlive, kValueAlive),
            ReadKeyFile());
}

TEST_F(KeyFileStoreTest, TrimWhitespaceBeforeKeyValuePair) {
  static const char kGroup[] = "the-group";
  static const char kKeyAlive[] = "alive";
  const int kValueAlive = 3;
  WriteKeyFile(
      base::StringPrintf("[%s]\n"
                         "    %s=%d\n",
                         kGroup, kKeyAlive, kValueAlive));
  ASSERT_TRUE(store_->Open());
  ASSERT_TRUE(store_->Close());
  EXPECT_EQ(base::StringPrintf("[%s]\n"
                               "%s=%d\n",
                               kGroup, kKeyAlive, kValueAlive),
            ReadKeyFile());
}

TEST_F(KeyFileStoreTest, TrimWhitespaceAroundKeyValueEquals) {
  static const char kGroup[] = "the-group";
  static const char kKey[] = "key";
  static const char kValue[] = "value";
  WriteKeyFile(
      base::StringPrintf("[%s]\n"
                         "%s  =  %s\n",
                         kGroup, kKey, kValue));
  ASSERT_TRUE(store_->Open());
  std::string value;
  EXPECT_TRUE(store_->GetString(kGroup, kKey, &value));
  EXPECT_EQ(kValue, value);
  ASSERT_TRUE(store_->Close());
  EXPECT_EQ(base::StringPrintf("[%s]\n"
                               "%s=%s\n",
                               kGroup, kKey, kValue),
            ReadKeyFile());
}

TEST_F(KeyFileStoreTest, PostGroupWhitespace) {
  // Tests consistent treatment of comment and whitespace lines at the end
  // of groups in glib key files.
  static const char kGroupA[] = "group-a";
  static const char kKeyA[] = "key-a";
  static const char kValueA[] = "value-a";
  static const char kGroupB[] = "group-b";
  static const char kCommentB[] = "#comment b";
  static const char kGroupC[] = "group-c";
  static const char kWhitespaceC[] = "      ";
  static const char kGroupD[] = "group-d";
  static const char kGroupE[] = "group-e";
  static const char kGroupF[] = "group-f";
  WriteKeyFile(
      base::StringPrintf("[%s]\n"
                         "%s=%s\n"
                         "[%s]\n"
                         "%s\n"
                         "[%s]\n"
                         "%s\n"
                         "[%s]\n"
                         "\n"
                         "[%s]\n"
                         "[%s]\n",
                         kGroupA, kKeyA, kValueA, kGroupB, kCommentB, kGroupC,
                         kWhitespaceC, kGroupD, kGroupE, kGroupF));
  ASSERT_TRUE(store_->Open());
  ASSERT_TRUE(store_->Close());
  EXPECT_EQ(
      base::StringPrintf("[%s]\n"
                         "%s=%s\n"
                         "\n"
                         "[%s]\n"
                         "%s\n"
                         "\n"
                         "[%s]\n"
                         "%s\n"
                         "\n"
                         "[%s]\n"
                         "\n"
                         "[%s]\n"
                         "\n"
                         "[%s]\n",
                         kGroupA, kKeyA, kValueA, kGroupB, kCommentB, kGroupC,
                         kWhitespaceC, kGroupD, kGroupE, kGroupF),
      ReadKeyFile());
}

TEST_F(KeyFileStoreTest, GetString) {
  static const char kGroup[] = "something";
  static const char kKey[] = "foo";
  static const char kValue[] = "bar";
  WriteKeyFile(
      base::StringPrintf("[%s]\n"
                         "%s=%s\n",
                         kGroup, kKey, kValue));
  ASSERT_TRUE(store_->Open());
  std::string value;
  EXPECT_TRUE(store_->GetString(kGroup, kKey, &value));
  EXPECT_EQ(kValue, value);
  EXPECT_FALSE(store_->GetString("something-else", kKey, &value));
  EXPECT_FALSE(store_->GetString(kGroup, "bar", &value));
  EXPECT_TRUE(store_->GetString(kGroup, kKey, nullptr));
  ASSERT_TRUE(store_->Close());
}

TEST_F(KeyFileStoreTest, UnescapeInitialWhitespaceInValue) {
  static const char kGroup[] = "the-group";
  static const char kKeyAlive[] = "alive";
  static const char kKeyDead[] = "dead";
  WriteKeyFile(
      base::StringPrintf("[%s]\n"
                         "%s=\\s foo\n"
                         "%s=\\t\tbar\n",
                         kGroup, kKeyAlive, kKeyDead));
  ASSERT_TRUE(store_->Open());
  std::string value;
  EXPECT_TRUE(store_->GetString(kGroup, kKeyAlive, &value));
  EXPECT_EQ(value, "  foo");
  EXPECT_TRUE(store_->GetString(kGroup, kKeyDead, &value));
  EXPECT_EQ(value, "\t\tbar");
}

TEST_F(KeyFileStoreTest, SetString) {
  static const char kGroup[] = "string-group";
  static const char kKey1[] = "test-string";
  static const char kValue1[] = "foo";
  static const char kKey2[] = "empty-string";
  static const char kValue2[] = "";
  ASSERT_TRUE(store_->Open());
  ASSERT_TRUE(store_->SetString(kGroup, kKey1, kValue1));
  ASSERT_TRUE(store_->SetString(kGroup, kKey2, kValue2));
  ASSERT_TRUE(store_->Close());
  EXPECT_EQ(base::StringPrintf("[%s]\n"
                               "%s=%s\n"
                               "%s=%s\n",
                               kGroup, kKey1, kValue1, kKey2, kValue2),
            ReadKeyFile());
}

TEST_F(KeyFileStoreTest, EscapeInitialWhitespaceInValue) {
  static const char kGroup[] = "the-group";
  static const char kKeyAlive[] = "alive";
  static const char kKeyDead[] = "dead";

  ASSERT_TRUE(store_->Open());
  EXPECT_TRUE(store_->SetString(kGroup, kKeyAlive, "  foo"));
  EXPECT_TRUE(store_->SetString(kGroup, kKeyDead, "\t\tbar"));
  ASSERT_TRUE(store_->Close());
  EXPECT_EQ(base::StringPrintf("[%s]\n"
                               "%s=\\s\\sfoo\n"
                               "%s=\\t\\tbar\n",
                               kGroup, kKeyAlive, kKeyDead),
            ReadKeyFile());
}

TEST_F(KeyFileStoreTest, GetBool) {
  static const char kGroup[] = "boo";
  static const char kKeyTrue[] = "foo";
  static const char kKeyFalse[] = "bar";
  static const char kKeyBad[] = "zoo";
  WriteKeyFile(
      base::StringPrintf("[%s]\n"
                         "%s=true\n"
                         "%s=false\n"
                         "%s=moo\n",
                         kGroup, kKeyTrue, kKeyFalse, kKeyBad));
  ASSERT_TRUE(store_->Open());
  {
    bool value = true;
    EXPECT_TRUE(store_->GetBool(kGroup, kKeyFalse, &value));
    EXPECT_FALSE(value);
  }
  {
    bool value = false;
    EXPECT_TRUE(store_->GetBool(kGroup, kKeyTrue, &value));
    EXPECT_TRUE(value);
  }
  {
    bool value;
    EXPECT_FALSE(store_->GetBool(kGroup, kKeyBad, &value));
    EXPECT_FALSE(store_->GetBool(kGroup, "unknown", &value));
    EXPECT_FALSE(store_->GetBool("unknown", kKeyTrue, &value));
  }
  EXPECT_TRUE(store_->GetBool(kGroup, kKeyFalse, nullptr));
  ASSERT_TRUE(store_->Close());
}

TEST_F(KeyFileStoreTest, SetBool) {
  static const char kGroup[] = "bool-group";
  static const char kKeyTrue[] = "test-true-bool";
  static const char kKeyFalse[] = "test-false-bool";
  ASSERT_TRUE(store_->Open());
  ASSERT_TRUE(store_->SetBool(kGroup, kKeyTrue, true));
  ASSERT_TRUE(store_->SetBool(kGroup, kKeyFalse, false));
  ASSERT_TRUE(store_->Close());
  EXPECT_EQ(base::StringPrintf("[%s]\n"
                               "%s=true\n"
                               "%s=false\n",
                               kGroup, kKeyTrue, kKeyFalse),
            ReadKeyFile());
}

TEST_F(KeyFileStoreTest, GetInt) {
  static const char kGroup[] = "numbers";
  static const char kKeyPos[] = "pos";
  static const char kKeyNeg[] = "neg";
  static const char kKeyBad[] = "bad";
  const int kValuePos = 50;
  const int kValueNeg = -20;
  static const char kValueBad[] = "nan";
  WriteKeyFile(base::StringPrintf(
      "[%s]\n"
      "%s=%d\n"
      "%s=%d\n"
      "%s=%s\n",
      kGroup, kKeyPos, kValuePos, kKeyNeg, kValueNeg, kKeyBad, kValueBad));
  ASSERT_TRUE(store_->Open());
  {
    int value = 0;
    EXPECT_TRUE(store_->GetInt(kGroup, kKeyNeg, &value));
    EXPECT_EQ(kValueNeg, value);
  }
  {
    int value = 0;
    EXPECT_TRUE(store_->GetInt(kGroup, kKeyPos, &value));
    EXPECT_EQ(kValuePos, value);
  }
  {
    int value;
    EXPECT_FALSE(store_->GetInt(kGroup, kKeyBad, &value));
    EXPECT_FALSE(store_->GetInt(kGroup, "invalid", &value));
    EXPECT_FALSE(store_->GetInt("invalid", kKeyPos, &value));
  }
  EXPECT_TRUE(store_->GetInt(kGroup, kKeyPos, nullptr));
  ASSERT_TRUE(store_->Close());
}

TEST_F(KeyFileStoreTest, SetInt) {
  static const char kGroup[] = "int-group";
  static const char kKey1[] = "test-int";
  static const char kKey2[] = "test-negative";
  const int kValue1 = 5;
  const int kValue2 = -10;
  ASSERT_TRUE(store_->Open());
  ASSERT_TRUE(store_->SetInt(kGroup, kKey1, kValue1));
  ASSERT_TRUE(store_->SetInt(kGroup, kKey2, kValue2));
  ASSERT_TRUE(store_->Close());
  EXPECT_EQ(base::StringPrintf("[%s]\n"
                               "%s=%d\n"
                               "%s=%d\n",
                               kGroup, kKey1, kValue1, kKey2, kValue2),
            ReadKeyFile());
}

TEST_F(KeyFileStoreTest, GetUint64) {
  static const char kGroup[] = "numbers";
  static const char kKeyGood[] = "good";
  static const char kKeyBad[] = "bad";
  const uint64_t kValueGood = 0xFEDCBA9876543210LL;
  static const char kValueBad[] = "nan";
  // Use base::NumberToString() instead of using something like "%llu"
  // (not correct for built-in 64 bit architectures) or PRIu64 (does not
  // work correctly using cros_workon_make due to include intricacies).
  WriteKeyFile(base::StringPrintf(
      "[%s]\n"
      "%s=%s\n"
      "%s=%s\n",
      kGroup, kKeyGood, base::NumberToString(kValueGood).c_str(), kKeyBad,
      kValueBad));
  ASSERT_TRUE(store_->Open());
  {
    uint64_t value = 0;
    EXPECT_TRUE(store_->GetUint64(kGroup, kKeyGood, &value));
    EXPECT_EQ(kValueGood, value);
  }
  {
    uint64_t value;
    EXPECT_FALSE(store_->GetUint64(kGroup, kKeyBad, &value));
    EXPECT_FALSE(store_->GetUint64(kGroup, "invalid", &value));
    EXPECT_FALSE(store_->GetUint64("invalid", kKeyGood, &value));
  }
  EXPECT_TRUE(store_->GetUint64(kGroup, kKeyGood, nullptr));
  ASSERT_TRUE(store_->Close());
}

TEST_F(KeyFileStoreTest, SetUint64) {
  static const char kGroup[] = "int-group";
  static const char kKey[] = "test-int";
  const uint64_t kValue = 0xFEDCBA9876543210LL;
  ASSERT_TRUE(store_->Open());
  ASSERT_TRUE(store_->SetUint64(kGroup, kKey, kValue));
  ASSERT_TRUE(store_->Close());
  EXPECT_EQ(
      base::StringPrintf("[%s]\n"
                         "%s=%s\n",
                         kGroup, kKey, base::NumberToString(kValue).c_str()),
      ReadKeyFile());
}

TEST_F(KeyFileStoreTest, GetInt64) {
  static const char kGroup[] = "numbers";
  static const char kKeyGood[] = "good";
  static const char kKeyBad[] = "bad";
  const int64_t kValueGood = 1836475854449306472;
  static const char kValueBad[] = "nan";
  // Use base::NumberToString() instead of using something like "%llu"
  // (not correct for built-in 64 bit architectures) or PRIu64 (does not
  // work correctly using cros_workon_make due to include intricacies).
  WriteKeyFile(base::StringPrintf(
      "[%s]\n"
      "%s=%s\n"
      "%s=%s\n",
      kGroup, kKeyGood, base::NumberToString(kValueGood).c_str(), kKeyBad,
      kValueBad));
  ASSERT_TRUE(store_->Open());
  {
    int64_t value = 0;
    EXPECT_TRUE(store_->GetInt64(kGroup, kKeyGood, &value));
    EXPECT_EQ(kValueGood, value);
  }
  {
    int64_t value;
    EXPECT_FALSE(store_->GetInt64(kGroup, kKeyBad, &value));
    EXPECT_FALSE(store_->GetInt64(kGroup, "invalid", &value));
    EXPECT_FALSE(store_->GetInt64("invalid", kKeyGood, &value));
  }
  EXPECT_TRUE(store_->GetInt64(kGroup, kKeyGood, nullptr));
  ASSERT_TRUE(store_->Close());
}

TEST_F(KeyFileStoreTest, SetInt64) {
  static const char kGroup[] = "int-group";
  static const char kKey[] = "test-int";
  const int64_t kValue = -1836475854449306470;
  ASSERT_TRUE(store_->Open());
  ASSERT_TRUE(store_->SetInt64(kGroup, kKey, kValue));
  ASSERT_TRUE(store_->Close());
  EXPECT_EQ(
      base::StringPrintf("[%s]\n"
                         "%s=%s\n",
                         kGroup, kKey, base::NumberToString(kValue).c_str()),
      ReadKeyFile());
}
TEST_F(KeyFileStoreTest, GetStringList) {
  static const char kGroup[] = "string-lists";
  static const char kKeyEmpty[] = "empty";
  static const char kKeyEmptyValue[] = "empty-value";
  static const char kKeyValue[] = "value";
  static const char kKeyValueEmpty[] = "value-empty";
  static const char kKeyValueEmptyValue[] = "value-empty-value";
  static const char kKeyValues[] = "values";
  static const char kValue[] = "value";
  static const char kValue2[] = "value2";
  static const char kValue3[] = "value3";
  WriteKeyFile(base::StringPrintf(
      "[%s]\n"
      "%s=\n"
      "%s=;%s\n"
      "%s=%s;\n"
      "%s=%s;;\n"
      "%s=%s;;%s\n"
      "%s=%s;%s;%s\n",
      kGroup, kKeyEmpty, kKeyEmptyValue, kValue, kKeyValue, kValue,
      kKeyValueEmpty, kValue, kKeyValueEmptyValue, kValue, kValue2, kKeyValues,
      kValue, kValue2, kValue3));
  ASSERT_TRUE(store_->Open());

  std::vector<std::string> value;

  EXPECT_TRUE(store_->GetStringList(kGroup, kKeyValues, &value));
  ASSERT_EQ(3, value.size());
  EXPECT_EQ(kValue, value[0]);
  EXPECT_EQ(kValue2, value[1]);
  EXPECT_EQ(kValue3, value[2]);

  EXPECT_TRUE(store_->GetStringList(kGroup, kKeyEmptyValue, &value));
  ASSERT_EQ(2, value.size());
  EXPECT_EQ("", value[0]);
  EXPECT_EQ(kValue, value[1]);

  EXPECT_TRUE(store_->GetStringList(kGroup, kKeyValue, &value));
  ASSERT_EQ(1, value.size());
  EXPECT_EQ(kValue, value[0]);

  EXPECT_TRUE(store_->GetStringList(kGroup, kKeyValueEmpty, &value));
  ASSERT_EQ(2, value.size());
  EXPECT_EQ(kValue, value[0]);
  EXPECT_EQ("", value[1]);

  EXPECT_TRUE(store_->GetStringList(kGroup, kKeyEmpty, &value));
  ASSERT_EQ(0, value.size());

  EXPECT_TRUE(store_->GetStringList(kGroup, kKeyValueEmptyValue, &value));
  ASSERT_EQ(3, value.size());
  EXPECT_EQ(kValue, value[0]);
  EXPECT_EQ("", value[1]);
  EXPECT_EQ(kValue2, value[2]);

  EXPECT_FALSE(
      store_->GetStringList("unknown-string-lists", kKeyEmpty, &value));
  EXPECT_FALSE(store_->GetStringList(kGroup, "some-key", &value));
  EXPECT_TRUE(store_->GetStringList(kGroup, kKeyValues, nullptr));
  ASSERT_TRUE(store_->Close());
}

TEST_F(KeyFileStoreTest, UnescapeSeparatorInList) {
  static const char kGroup[] = "tama-town";
  static const char kKey[] = "residents";

  WriteKeyFile(
      base::StringPrintf("[%s]\n"
                         "%s="
                         "GN=Yuuko\\;FN=Yoshida\\;NN=Shamiko;"
                         "GN=Momo\\;FN=Chiyoda\\;NN=Fresh Peach;\n",
                         kGroup, kKey));
  ASSERT_TRUE(store_->Open());
  std::vector<std::string> value;
  EXPECT_TRUE(store_->GetStringList(kGroup, kKey, &value));
  EXPECT_EQ(2, value.size());
  EXPECT_EQ(value[0], "GN=Yuuko;FN=Yoshida;NN=Shamiko");
  EXPECT_EQ(value[1], "GN=Momo;FN=Chiyoda;NN=Fresh Peach");
}

TEST_F(KeyFileStoreTest, SetStringList) {
  static const char kGroup[] = "strings";
  static const char kKeyEmpty[] = "e";
  static const char kKeyValue[] = "v";
  static const char kKeyEmptyValue[] = "ev";
  static const char kKeyValueEmpty[] = "ve";
  static const char kKeyValueEmptyValue[] = "vev";
  static const char kKeyValues[] = "vvv";
  static const char kValue[] = "abc";
  static const char kValue2[] = "pqr";
  static const char kValue3[] = "xyz";
  ASSERT_TRUE(store_->Open());
  ASSERT_TRUE(store_->SetStringList(kGroup, kKeyEmpty, {}));
  ASSERT_TRUE(store_->SetStringList(kGroup, kKeyValue, {kValue}));
  ASSERT_TRUE(store_->SetStringList(kGroup, kKeyEmptyValue, {"", kValue}));
  ASSERT_TRUE(store_->SetStringList(kGroup, kKeyValueEmpty, {kValue, ""}));
  ASSERT_TRUE(store_->SetStringList(kGroup, kKeyValueEmptyValue,
                                    {kValue, "", kValue2}));
  ASSERT_TRUE(
      store_->SetStringList(kGroup, kKeyValues, {kValue, kValue2, kValue3}));
  ASSERT_TRUE(store_->Close());
  EXPECT_EQ(
      base::StringPrintf("[%s]\n"
                         "%s=\n"
                         "%s=%s;\n"
                         "%s=;%s;\n"
                         "%s=%s;;\n"
                         "%s=%s;;%s;\n"
                         "%s=%s;%s;%s;\n",
                         kGroup, kKeyEmpty, kKeyValue, kValue, kKeyEmptyValue,
                         kValue, kKeyValueEmpty, kValue, kKeyValueEmptyValue,
                         kValue, kValue2, kKeyValues, kValue, kValue2, kValue3),
      ReadKeyFile());
}

TEST_F(KeyFileStoreTest, EscapeSeparatorInList) {
  static const char kGroup[] = "tama-town";
  static const char kKey[] = "residents";

  ASSERT_TRUE(store_->Open());
  EXPECT_TRUE(store_->SetStringList(
      kGroup, kKey,
      {"GN=Yuuko;FN=Yoshida;NN=Shamiko", "GN=Momo;FN=Chiyoda;NN=Fresh Peach"}));
  ASSERT_TRUE(store_->Close());
  EXPECT_EQ(base::StringPrintf("[%s]\n"
                               "%s="
                               "GN=Yuuko\\;FN=Yoshida\\;NN=Shamiko;"
                               "GN=Momo\\;FN=Chiyoda\\;NN=Fresh Peach;\n",
                               kGroup, kKey),
            ReadKeyFile());
}

TEST_F(KeyFileStoreTest, GetDeprecatedCryptedString) {
  static const char kPlainText[] = "This is a test!";
  static const char kROT47Text[] = "rot47:%9:D :D 2 E6DEP";

  static const char kGroup[] = "crypto-group";
  static const char kDeprecatedKey[] = "deprecated";
  static const char kPlaintextKey[] = "plaintext";
  WriteKeyFile(
      base::StringPrintf("[%s]\n"
                         "%s=%s\n",
                         kGroup, kDeprecatedKey, kROT47Text));
  ASSERT_TRUE(store_->Open());
  std::string value;
  EXPECT_TRUE(
      store_->GetCryptedString(kGroup, kDeprecatedKey, kPlaintextKey, &value));
  EXPECT_EQ(kPlainText, value);
  EXPECT_FALSE(store_->GetCryptedString("something-else", kDeprecatedKey,
                                        kPlaintextKey, &value));
  EXPECT_FALSE(store_->GetCryptedString(kGroup, "non-secret-deprecated",
                                        "non-secret", &value));
  EXPECT_TRUE(
      store_->GetCryptedString(kGroup, kDeprecatedKey, kPlaintextKey, nullptr));
  ASSERT_TRUE(store_->Close());
}

TEST_F(KeyFileStoreTest, PersistAcrossClose) {
  static const char kGroup[] = "string-group";
  static const char kKey1[] = "test-string";
  static const char kValue1[] = "foo";
  static const char kKey2[] = "empty-string";
  static const char kValue2[] = "";
  ASSERT_TRUE(store_->Open());
  ASSERT_TRUE(store_->SetString(kGroup, kKey1, kValue1));
  ASSERT_TRUE(store_->Close());
  ASSERT_TRUE(store_->Open());
  ASSERT_TRUE(store_->SetString(kGroup, kKey2, kValue2));
  std::string value;
  ASSERT_TRUE(store_->GetString(kGroup, kKey1, &value));
  ASSERT_EQ(kValue1, value);
  ASSERT_TRUE(store_->GetString(kGroup, kKey2, &value));
  ASSERT_EQ(kValue2, value);
  ASSERT_TRUE(store_->Close());
}

TEST_F(KeyFileStoreTest, GetUint64List) {
  static const char kGroup[] = "uint64-lists";
  static const char kKeyEmpty[] = "empty";
  static const char kKeyValue[] = "value";
  static const char kKeyTwoValues[] = "two-values";
  static const char kKeyValues[] = "values";
  static const uint64_t kValue = 1234567890ull;
  static const uint64_t kValue2 = 9876543210ull;
  static const uint64_t kValue3 = std::numeric_limits<uint64_t>::max();
  WriteKeyFile(
      base::StringPrintf("[%s]\n"
                         "%s=\n"
                         "%s=%" PRIu64 "\n"
                         "%s=%" PRIu64 ";%" PRIu64 "\n"
                         "%s=%" PRIu64 ";%" PRIu64 ";%" PRIu64 "\n",
                         kGroup, kKeyEmpty, kKeyValue, kValue, kKeyTwoValues,
                         kValue, kValue2, kKeyValues, kValue, kValue2,
                         kValue3));
  ASSERT_TRUE(store_->Open());

  std::vector<uint64_t> value;

  EXPECT_TRUE(store_->GetUint64List(kGroup, kKeyValues, &value));
  ASSERT_EQ(3, value.size());
  EXPECT_EQ(kValue, value[0]);
  EXPECT_EQ(kValue2, value[1]);
  EXPECT_EQ(kValue3, value[2]);

  EXPECT_TRUE(store_->GetUint64List(kGroup, kKeyEmpty, &value));
  ASSERT_EQ(0, value.size());

  EXPECT_TRUE(store_->GetUint64List(kGroup, kKeyValue, &value));
  ASSERT_EQ(1, value.size());
  EXPECT_EQ(kValue, value[0]);

  EXPECT_TRUE(store_->GetUint64List(kGroup, kKeyTwoValues, &value));
  ASSERT_EQ(2, value.size());
  EXPECT_EQ(kValue, value[0]);
  EXPECT_EQ(kValue2, value[1]);

  EXPECT_FALSE(
      store_->GetUint64List("unknown-uint64-lists", kKeyEmpty, &value));
  EXPECT_FALSE(store_->GetUint64List(kGroup, "some-key", &value));
  EXPECT_TRUE(store_->GetUint64List(kGroup, kKeyValues, nullptr));
  ASSERT_TRUE(store_->Close());
}

TEST_F(KeyFileStoreTest, SetUint64List) {
  static const char kGroup[] = "unsigned-ints";
  static const char kKeyEmpty[] = "e";
  static const char kKeyValue[] = "v";
  static const char kKeyTwoValues[] = "vv";
  static const char kKeyValues[] = "vvv";
  static const uint64_t kValue = 11111111;
  static const uint64_t kValue2 = 8888888888;
  static const uint64_t kValue3 = std::numeric_limits<uint64_t>::max();
  ASSERT_TRUE(store_->Open());
  ASSERT_TRUE(store_->SetUint64List(kGroup, kKeyEmpty, {}));
  ASSERT_TRUE(store_->SetUint64List(kGroup, kKeyValue, {kValue}));
  ASSERT_TRUE(store_->SetUint64List(kGroup, kKeyTwoValues, {kValue, kValue2}));
  ASSERT_TRUE(
      store_->SetUint64List(kGroup, kKeyValues, {kValue, kValue2, kValue3}));
  ASSERT_TRUE(store_->Close());
  EXPECT_EQ(
      base::StringPrintf("[%s]\n"
                         "%s=\n"
                         "%s=%" PRIu64 ";\n"
                         "%s=%" PRIu64 ";%" PRIu64 ";\n"
                         "%s=%" PRIu64 ";%" PRIu64 ";%" PRIu64 ";\n",
                         kGroup, kKeyEmpty, kKeyValue, kValue, kKeyTwoValues,
                         kValue, kValue2, kKeyValues, kValue, kValue2, kValue3),
      ReadKeyFile());
}

TEST_F(KeyFileStoreTest, SetAndGetStringmaps) {
  // Store a Stringmaps and verify that the escaped string used to store the
  // Stringmaps can be stored inside another Stringmaps.
  static const char kGroup[] = "group1";
  static const char kKeyStringmapsEmpty[] = "e";
  static const char kKeyStringmapsValue[] = "v";
  static const char kKeyStringmapsInception[] = "v-inception";
  static const char kMapKey1[] = "key1";
  static const char kMapKey2[] = "key2";
  static const char kValueString1[] = "\n\t\\&&%$\\#$5*9(;,.;,.;\n~`.;'\"";
  static const char kValueString2[] = "%{}};;;.,;}^&\n^\\/\\/%$;,;.\r🤯";
  static const Stringmaps smaps = {
      {{kMapKey1, kValueString1}, {kMapKey2, kValueString2}},
      {{kMapKey2, kValueString1}}};
  ASSERT_TRUE(store_->Open());
  ASSERT_TRUE(store_->SetStringmaps(kGroup, kKeyStringmapsEmpty, {}));
  ASSERT_TRUE(store_->SetStringmaps(kGroup, kKeyStringmapsValue, smaps));
  ASSERT_TRUE(store_->Close());
  // Read JSON Stringmaps as a string, and store it inside another Stringmaps
  ASSERT_TRUE(store_->Open());
  std::string stringmapsJson;
  ASSERT_TRUE(store_->GetString(kGroup, kKeyStringmapsValue, &stringmapsJson));
  static const Stringmaps smaps2 = {{{kMapKey1, stringmapsJson}}};
  ASSERT_TRUE(store_->SetStringmaps(kGroup, kKeyStringmapsInception, smaps2));
  ASSERT_TRUE(store_->Close());
  // Verify the value inside |kKeyStringmapsInception| matches |stringmapsJson|
  ASSERT_TRUE(store_->Open());
  Stringmaps smaps_value;
  ASSERT_TRUE(
      store_->GetStringmaps(kGroup, kKeyStringmapsInception, &smaps_value));
  ASSERT_EQ(1, smaps_value.size());
  ASSERT_EQ(1, smaps_value[0].size());
  ASSERT_EQ(stringmapsJson, smaps_value[0][kMapKey1]);
  // Verify the contents of |kKeyStringmapsValue|
  ASSERT_TRUE(store_->GetStringmaps(kGroup, kKeyStringmapsValue, &smaps_value));
  ASSERT_EQ(2, smaps_value.size());
  ASSERT_EQ(2, smaps_value[0].size());
  ASSERT_EQ(1, smaps_value[1].size());
  ASSERT_EQ(kValueString1, smaps_value[0][kMapKey1]);
  ASSERT_EQ(kValueString2, smaps_value[0][kMapKey2]);
  ASSERT_EQ(kValueString1, smaps_value[1][kMapKey2]);
  ASSERT_EQ(smaps, smaps_value);

  ASSERT_TRUE(store_->GetStringmaps(kGroup, kKeyStringmapsEmpty, &smaps_value));
  ASSERT_EQ(0, smaps_value.size());
  ASSERT_TRUE(store_->Close());
}

namespace {
class ReadOnlyKeyFileStore : public KeyFileStore {
 public:
  explicit ReadOnlyKeyFileStore(const base::FilePath& path)
      : KeyFileStore(path) {}
  bool Flush() override { return true; }
};

bool OpenCheckClose(const base::FilePath& path,
                    const std::string& group,
                    const std::string& key,
                    const std::string& expected_value) {
  ReadOnlyKeyFileStore store(path);  // Don't modify file owned by caller.
  EXPECT_TRUE(store.Open());
  std::string value;
  bool could_get = store.GetString(group, key, &value);
  store.Close();
  return could_get && expected_value == value;
}

TEST_F(KeyFileStoreTest, Flush) {
  static const char kGroup[] = "string-group";
  static const char kKey1[] = "test-string";
  static const char kValue1[] = "foo";
  static const char kKey2[] = "empty-string";
  static const char kValue2[] = "";
  ASSERT_TRUE(store_->Open());
  ASSERT_TRUE(store_->SetString(kGroup, kKey1, kValue1));
  ASSERT_TRUE(store_->Flush());
  ASSERT_TRUE(OpenCheckClose(test_file_, kGroup, kKey1, kValue1));

  ASSERT_TRUE(store_->SetString(kGroup, kKey2, kValue2));
  ASSERT_TRUE(store_->Flush());
  ASSERT_TRUE(OpenCheckClose(test_file_, kGroup, kKey2, kValue2));

  EXPECT_TRUE(store_->DeleteKey(kGroup, kKey1));
  ASSERT_TRUE(store_->Flush());
  ASSERT_FALSE(OpenCheckClose(test_file_, kGroup, kKey1, kValue1));
}
}  // namespace

TEST_F(KeyFileStoreTest, EmptyFile) {
  ASSERT_TRUE(store_->Open());
  ASSERT_TRUE(store_->Close());
  EXPECT_TRUE(store_->IsEmpty());
}

TEST_F(KeyFileStoreTest, SetHeader) {
  ASSERT_TRUE(store_->Open());
  ASSERT_TRUE(store_->SetHeader("this is a test"));
  ASSERT_TRUE(store_->Close());
  EXPECT_FALSE(store_->IsEmpty());
  ASSERT_TRUE(store_->Open());
}

TEST_F(KeyFileStoreTest, Combo) {
  static const char kGroupA[] = "square";
  static const char kGroupB[] = "circle";
  static const char kGroupC[] = "triangle";
  static const char kGroupX[] = "pentagon";
  static const char kKeyString[] = "color";
  static const char kKeyString2[] = "color2";
  static const char kKeyStringList[] = "alternative-colors";
  static const char kKeyStringmaps[] = "colors-options";
  static const char kKeyInt[] = "area";
  static const char kKeyBool[] = "visible";
  static const char kValueStringA[] = "blue";
  static const char kValueStringB[] = "red";
  static const char kValueStringC[] = "yellow";
  static const char kValueStringCNew[] = "purple";
  const int kValueIntA = 5;
  const int kValueIntB = 10;
  const int kValueIntBNew = 333;
  WriteKeyFile(base::StringPrintf(
      "[%s]\n"  // Group A
      "%s=%s\n"
      "%s=%s;%s\n"
      "%s=%d\n"
      "%s=[{\"%s\":\"%s\",\"%s\":\"%s\"},{\"%s\":\"%s\",\"%s\":\"%s\"}]\n"
      "[%s]\n"  // Group B
      "%s=%s\n"
      "%s=%s;%s\n"
      "%s=%d\n"
      "%s=true\n"
      "[%s]\n"  // Group C
      "%s=%s\n"
      "%s=false\n",
      // Group A
      kGroupA, kKeyString, kValueStringA, kKeyStringList, kValueStringB,
      kValueStringC, kKeyInt, kValueIntA,
      // Stringmaps
      kKeyStringmaps, kKeyString, kValueStringA, kKeyString2, kValueStringB,
      kKeyString, kValueStringB, kKeyString2, kValueStringC,
      // Group B
      kGroupB, kKeyString, kValueStringB, kKeyStringList, kValueStringA,
      kValueStringC, kKeyInt, kValueIntB, kKeyBool,
      // Group C
      kGroupC, kKeyString, kValueStringC, kKeyBool));
  ASSERT_TRUE(store_->Open());

  EXPECT_TRUE(store_->ContainsGroup(kGroupA));
  EXPECT_TRUE(store_->ContainsGroup(kGroupB));
  EXPECT_TRUE(store_->ContainsGroup(kGroupC));
  EXPECT_FALSE(store_->ContainsGroup(kGroupX));

  std::set<std::string> groups = store_->GetGroups();
  EXPECT_EQ(3, groups.size());
  EXPECT_TRUE(base::Contains(groups, kGroupA));
  EXPECT_TRUE(base::Contains(groups, kGroupB));
  EXPECT_TRUE(base::Contains(groups, kGroupC));
  EXPECT_FALSE(base::Contains(groups, kGroupX));

  {
    std::string value;
    EXPECT_TRUE(store_->GetString(kGroupB, kKeyString, &value));
    EXPECT_EQ(kValueStringB, value);
    EXPECT_TRUE(store_->GetString(kGroupA, kKeyString, &value));
    EXPECT_EQ(kValueStringA, value);
    EXPECT_TRUE(store_->GetString(kGroupC, kKeyString, &value));
    EXPECT_EQ(kValueStringC, value);
  }
  {
    std::vector<std::string> value;
    EXPECT_TRUE(store_->GetStringList(kGroupB, kKeyStringList, &value));
    ASSERT_EQ(2, value.size());
    EXPECT_EQ(kValueStringA, value[0]);
    EXPECT_EQ(kValueStringC, value[1]);
    EXPECT_TRUE(store_->GetStringList(kGroupA, kKeyStringList, &value));
    ASSERT_EQ(2, value.size());
    EXPECT_EQ(kValueStringB, value[0]);
    EXPECT_EQ(kValueStringC, value[1]);
    EXPECT_FALSE(store_->GetStringList(kGroupC, kKeyStringList, &value));
  }
  {
    shill::Stringmaps value;
    shill::Stringmap value0 = {{kKeyString, kValueStringA},
                               {kKeyString2, kValueStringB}};
    shill::Stringmap value1 = {{kKeyString, kValueStringB},
                               {kKeyString2, kValueStringC}};
    EXPECT_FALSE(store_->GetStringmaps(kGroupB, kKeyStringmaps, &value));
    EXPECT_TRUE(store_->GetStringmaps(kGroupA, kKeyStringmaps, &value));
    ASSERT_EQ(2, value.size());
    EXPECT_EQ(value0, value[0]);
    EXPECT_EQ(value1, value[1]);
    EXPECT_FALSE(store_->GetStringmaps(kGroupC, kKeyStringmaps, &value));
  }
  {
    int value = 0;
    EXPECT_TRUE(store_->GetInt(kGroupB, kKeyInt, &value));
    EXPECT_EQ(kValueIntB, value);
    EXPECT_TRUE(store_->GetInt(kGroupA, kKeyInt, &value));
    EXPECT_EQ(kValueIntA, value);
    EXPECT_FALSE(store_->GetInt(kGroupC, kKeyInt, &value));
  }
  {
    bool value = false;
    EXPECT_TRUE(store_->GetBool(kGroupB, kKeyBool, &value));
    EXPECT_TRUE(value);
    EXPECT_TRUE(store_->GetBool(kGroupC, kKeyBool, &value));
    EXPECT_FALSE(value);
    EXPECT_FALSE(store_->GetBool(kGroupA, kKeyBool, &value));
  }

  EXPECT_TRUE(store_->DeleteGroup(kGroupA));
  EXPECT_FALSE(store_->DeleteGroup(kGroupA));

  EXPECT_FALSE(store_->ContainsGroup(kGroupA));
  EXPECT_TRUE(store_->ContainsGroup(kGroupB));
  EXPECT_TRUE(store_->ContainsGroup(kGroupC));

  groups = store_->GetGroups();
  EXPECT_EQ(2, groups.size());
  EXPECT_FALSE(base::Contains(groups, kGroupA));
  EXPECT_TRUE(base::Contains(groups, kGroupB));
  EXPECT_TRUE(base::Contains(groups, kGroupC));

  EXPECT_TRUE(store_->SetBool(kGroupB, kKeyBool, false));
  EXPECT_TRUE(store_->SetInt(kGroupB, kKeyInt, kValueIntBNew));
  EXPECT_TRUE(store_->SetString(kGroupC, kKeyString, kValueStringCNew));
  store_->SetStringList(kGroupB, kKeyStringList,
                        std::vector<std::string>(1, kValueStringB));

  EXPECT_TRUE(store_->DeleteKey(kGroupB, kKeyString));
  EXPECT_FALSE(store_->DeleteKey(kGroupB, kKeyString));

  {
    std::string value;
    EXPECT_FALSE(store_->GetString(kGroupB, kKeyString, &value));
    EXPECT_FALSE(store_->GetString(kGroupA, kKeyString, &value));
    EXPECT_TRUE(store_->GetString(kGroupC, kKeyString, &value));
    EXPECT_EQ(kValueStringCNew, value);
  }
  {
    std::vector<std::string> value;
    EXPECT_TRUE(store_->GetStringList(kGroupB, kKeyStringList, &value));
    ASSERT_EQ(1, value.size());
    EXPECT_EQ(kValueStringB, value[0]);
    EXPECT_FALSE(store_->GetStringList(kGroupA, kKeyStringList, &value));
    EXPECT_FALSE(store_->GetStringList(kGroupC, kKeyStringList, &value));
  }
  {
    int value = 0;
    EXPECT_TRUE(store_->GetInt(kGroupB, kKeyInt, &value));
    EXPECT_EQ(kValueIntBNew, value);
    EXPECT_FALSE(store_->GetInt(kGroupA, kKeyInt, &value));
    EXPECT_FALSE(store_->GetInt(kGroupC, kKeyInt, &value));
  }
  {
    bool value = false;
    EXPECT_TRUE(store_->GetBool(kGroupB, kKeyBool, &value));
    EXPECT_FALSE(value);
    EXPECT_TRUE(store_->GetBool(kGroupC, kKeyBool, &value));
    EXPECT_FALSE(value);
    EXPECT_FALSE(store_->GetBool(kGroupA, kKeyBool, &value));
  }

  ASSERT_TRUE(store_->Close());
  EXPECT_EQ(base::StringPrintf("[%s]\n"
                               "%s=%s;\n"
                               "%s=%d\n"
                               "%s=false\n"
                               "\n"
                               "[%s]\n"
                               "%s=%s\n"
                               "%s=false\n",
                               kGroupB, kKeyStringList, kValueStringB, kKeyInt,
                               kValueIntBNew, kKeyBool, kGroupC, kKeyString,
                               kValueStringCNew, kKeyBool),
            ReadKeyFile());
}

}  // namespace shill
