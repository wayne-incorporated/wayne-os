// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/setup/xml/android_binary_xml_tokenizer.h"

#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

#include "arc/setup/xml/android_binary_xml_tokenizer_test_util.h"

namespace arc {

namespace {

using Token = AndroidBinaryXmlTokenizer::Token;
using Type = AndroidBinaryXmlTokenizer::Type;

class AndroidBinaryXmlTokenizerTest : public testing::Test {
 public:
  AndroidBinaryXmlTokenizerTest() = default;
  AndroidBinaryXmlTokenizerTest(const AndroidBinaryXmlTokenizerTest&) = delete;
  AndroidBinaryXmlTokenizerTest& operator=(
      const AndroidBinaryXmlTokenizerTest&) = delete;
  ~AndroidBinaryXmlTokenizerTest() override = default;

  // testing::Test:
  void SetUp() override {
    // Create the test file.
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    test_file_path_ = temp_dir_.GetPath().AppendASCII("test.xml");
    ASSERT_TRUE(writer_.Init(test_file_path_));
  }

 protected:
  base::ScopedTempDir temp_dir_;

  // Test file.
  base::FilePath test_file_path_;

  AndroidBinaryXmlWriter writer_;
};

TEST_F(AndroidBinaryXmlTokenizerTest, Empty) {
  AndroidBinaryXmlTokenizer tokenizer;
  ASSERT_TRUE(tokenizer.Init(test_file_path_));

  EXPECT_FALSE(tokenizer.is_eof());
  EXPECT_FALSE(tokenizer.Next());
  EXPECT_TRUE(tokenizer.is_eof());
}

TEST_F(AndroidBinaryXmlTokenizerTest, StartAndEndDocument) {
  // Android's serializer usually puts these tokens at the beginning and the end
  // of an Android binary XML file.
  ASSERT_TRUE(writer_.WriteToken(Token::kStartDocument, Type::kNull));
  ASSERT_TRUE(writer_.WriteToken(Token::kEndDocument, Type::kNull));

  AndroidBinaryXmlTokenizer tokenizer;
  ASSERT_TRUE(tokenizer.Init(test_file_path_));

  ASSERT_TRUE(tokenizer.Next());
  EXPECT_EQ(tokenizer.token(), Token::kStartDocument);
  ASSERT_TRUE(tokenizer.Next());
  EXPECT_EQ(tokenizer.token(), Token::kEndDocument);
  EXPECT_FALSE(tokenizer.Next());
  EXPECT_TRUE(tokenizer.is_eof());
}

TEST_F(AndroidBinaryXmlTokenizerTest, StartAndEndTag) {
  constexpr char kTagName[] = "foo";

  // A start tag consists of a token and name as an interned string.
  // This is <foo> in text XML.
  ASSERT_TRUE(writer_.WriteToken(Token::kStartTag, Type::kStringInterned));
  ASSERT_TRUE(writer_.WriteInternedString(kTagName));

  // An end tag consists of a token and name as an interned string.
  // This is </foo> in text XML.
  ASSERT_TRUE(writer_.WriteToken(Token::kEndTag, Type::kStringInterned));
  ASSERT_TRUE(writer_.WriteInternedString(kTagName));

  AndroidBinaryXmlTokenizer tokenizer;
  ASSERT_TRUE(tokenizer.Init(test_file_path_));

  ASSERT_TRUE(tokenizer.Next());
  EXPECT_EQ(tokenizer.token(), Token::kStartTag);
  EXPECT_EQ(tokenizer.name(), kTagName);
  EXPECT_EQ(tokenizer.depth(), 1);  // depth++ when entering a tag.

  ASSERT_TRUE(tokenizer.Next());
  EXPECT_EQ(tokenizer.token(), Token::kEndTag);
  EXPECT_EQ(tokenizer.name(), kTagName);
  EXPECT_EQ(tokenizer.depth(), 0);  // depth-- when exiting a tag.

  EXPECT_FALSE(tokenizer.Next());
  EXPECT_TRUE(tokenizer.is_eof());
}

TEST_F(AndroidBinaryXmlTokenizerTest, StringAttribute) {
  constexpr char kAttributeName[] = "foo";
  constexpr char kAttributeValue[] = "bar";

  // This is foo="bar" in text XML.
  ASSERT_TRUE(writer_.WriteToken(Token::kAttribute, Type::kString));
  ASSERT_TRUE(writer_.WriteInternedString(kAttributeName));
  ASSERT_TRUE(writer_.WriteString(kAttributeValue));

  AndroidBinaryXmlTokenizer tokenizer;
  ASSERT_TRUE(tokenizer.Init(test_file_path_));

  ASSERT_TRUE(tokenizer.Next());
  EXPECT_EQ(tokenizer.token(), Token::kAttribute);
  EXPECT_EQ(tokenizer.type(), Type::kString);
  EXPECT_EQ(tokenizer.name(), kAttributeName);
  EXPECT_EQ(tokenizer.string_value(), kAttributeValue);
  EXPECT_FALSE(tokenizer.Next());
  EXPECT_TRUE(tokenizer.is_eof());
}

TEST_F(AndroidBinaryXmlTokenizerTest, InternedStringAttribute) {
  constexpr char kAttributeName[] = "foo";
  constexpr char kAttributeValue[] = "bar";

  // This is foo="bar" in text XML.
  ASSERT_TRUE(writer_.WriteToken(Token::kAttribute, Type::kStringInterned));
  ASSERT_TRUE(writer_.WriteInternedString(kAttributeName));
  ASSERT_TRUE(writer_.WriteInternedString(kAttributeValue));

  AndroidBinaryXmlTokenizer tokenizer;
  ASSERT_TRUE(tokenizer.Init(test_file_path_));

  ASSERT_TRUE(tokenizer.Next());
  EXPECT_EQ(tokenizer.token(), Token::kAttribute);
  EXPECT_EQ(tokenizer.type(), Type::kStringInterned);
  EXPECT_EQ(tokenizer.name(), kAttributeName);
  EXPECT_EQ(tokenizer.string_value(), kAttributeValue);
  EXPECT_FALSE(tokenizer.Next());
  EXPECT_TRUE(tokenizer.is_eof());
}

TEST_F(AndroidBinaryXmlTokenizerTest, BytesHexAttribute) {
  constexpr char kAttributeName[] = "foo";
  constexpr uint8_t kAttributeValue[] = {0, 1, 2, 3};

  // This is foo="00010203" in text XML.
  ASSERT_TRUE(writer_.WriteToken(Token::kAttribute, Type::kBytesHex));
  ASSERT_TRUE(writer_.WriteInternedString(kAttributeName));
  ASSERT_TRUE(writer_.WriteUint16(sizeof(kAttributeValue)));
  ASSERT_TRUE(writer_.WriteData(kAttributeValue, sizeof(kAttributeValue)));

  AndroidBinaryXmlTokenizer tokenizer;
  ASSERT_TRUE(tokenizer.Init(test_file_path_));

  ASSERT_TRUE(tokenizer.Next());
  EXPECT_EQ(tokenizer.token(), Token::kAttribute);
  EXPECT_EQ(tokenizer.type(), Type::kBytesHex);
  EXPECT_EQ(tokenizer.name(), kAttributeName);
  EXPECT_EQ(tokenizer.bytes_value(),
            std::vector<uint8_t>(kAttributeValue,
                                 kAttributeValue + sizeof(kAttributeValue)));
  EXPECT_FALSE(tokenizer.Next());
  EXPECT_TRUE(tokenizer.is_eof());
}

TEST_F(AndroidBinaryXmlTokenizerTest, BytesBase64Attribute) {
  constexpr char kAttributeName[] = "foo";
  constexpr uint8_t kAttributeValue[] = {0, 1, 2, 3};

  // This is foo="<base64 encoded data>" in text XML.
  ASSERT_TRUE(writer_.WriteToken(Token::kAttribute, Type::kBytesBase64));
  ASSERT_TRUE(writer_.WriteInternedString(kAttributeName));
  ASSERT_TRUE(writer_.WriteUint16(sizeof(kAttributeValue)));
  ASSERT_TRUE(writer_.WriteData(kAttributeValue, sizeof(kAttributeValue)));

  AndroidBinaryXmlTokenizer tokenizer;
  ASSERT_TRUE(tokenizer.Init(test_file_path_));

  ASSERT_TRUE(tokenizer.Next());
  EXPECT_EQ(tokenizer.token(), Token::kAttribute);
  EXPECT_EQ(tokenizer.type(), Type::kBytesBase64);
  EXPECT_EQ(tokenizer.name(), kAttributeName);
  EXPECT_EQ(tokenizer.bytes_value(),
            std::vector<uint8_t>(kAttributeValue,
                                 kAttributeValue + sizeof(kAttributeValue)));
  EXPECT_FALSE(tokenizer.Next());
  EXPECT_TRUE(tokenizer.is_eof());
}

TEST_F(AndroidBinaryXmlTokenizerTest, IntAttribute) {
  constexpr char kAttributeName[] = "foo";
  constexpr int32_t kAttributeValue = -123456;

  // This is foo="-123456" in text XML.
  ASSERT_TRUE(writer_.WriteToken(Token::kAttribute, Type::kInt));
  ASSERT_TRUE(writer_.WriteInternedString(kAttributeName));
  ASSERT_TRUE(writer_.WriteInt32(kAttributeValue));

  AndroidBinaryXmlTokenizer tokenizer;
  ASSERT_TRUE(tokenizer.Init(test_file_path_));

  ASSERT_TRUE(tokenizer.Next());
  EXPECT_EQ(tokenizer.token(), Token::kAttribute);
  EXPECT_EQ(tokenizer.type(), Type::kInt);
  EXPECT_EQ(tokenizer.name(), kAttributeName);
  EXPECT_EQ(tokenizer.int_value(), kAttributeValue);
  EXPECT_FALSE(tokenizer.Next());
  EXPECT_TRUE(tokenizer.is_eof());
}

TEST_F(AndroidBinaryXmlTokenizerTest, IntHexAttribute) {
  constexpr char kAttributeName[] = "foo";
  constexpr int32_t kAttributeValue = 0xabcdef;

  // This is foo="abcdef" in text XML.
  ASSERT_TRUE(writer_.WriteToken(Token::kAttribute, Type::kIntHex));
  ASSERT_TRUE(writer_.WriteInternedString(kAttributeName));
  ASSERT_TRUE(writer_.WriteInt32(kAttributeValue));

  AndroidBinaryXmlTokenizer tokenizer;
  ASSERT_TRUE(tokenizer.Init(test_file_path_));

  ASSERT_TRUE(tokenizer.Next());
  EXPECT_EQ(tokenizer.token(), Token::kAttribute);
  EXPECT_EQ(tokenizer.type(), Type::kIntHex);
  EXPECT_EQ(tokenizer.name(), kAttributeName);
  EXPECT_EQ(tokenizer.int_value(), kAttributeValue);
  EXPECT_FALSE(tokenizer.Next());
  EXPECT_TRUE(tokenizer.is_eof());
}

TEST_F(AndroidBinaryXmlTokenizerTest, LongAttribute) {
  constexpr char kAttributeName[] = "foo";
  constexpr int64_t kAttributeValue = -1234567890;

  // This is foo="-1234567890" in text XML.
  ASSERT_TRUE(writer_.WriteToken(Token::kAttribute, Type::kLong));
  ASSERT_TRUE(writer_.WriteInternedString(kAttributeName));
  ASSERT_TRUE(writer_.WriteInt64(kAttributeValue));

  AndroidBinaryXmlTokenizer tokenizer;
  ASSERT_TRUE(tokenizer.Init(test_file_path_));

  ASSERT_TRUE(tokenizer.Next());
  EXPECT_EQ(tokenizer.token(), Token::kAttribute);
  EXPECT_EQ(tokenizer.type(), Type::kLong);
  EXPECT_EQ(tokenizer.name(), kAttributeName);
  EXPECT_EQ(tokenizer.int_value(), kAttributeValue);
  EXPECT_FALSE(tokenizer.Next());
  EXPECT_TRUE(tokenizer.is_eof());
}

TEST_F(AndroidBinaryXmlTokenizerTest, LongHexAttribute) {
  constexpr char kAttributeName[] = "foo";
  constexpr int64_t kAttributeValue = 0xabcdef012345;

  // This is foo="abcdef012345" in text XML.
  ASSERT_TRUE(writer_.WriteToken(Token::kAttribute, Type::kLongHex));
  ASSERT_TRUE(writer_.WriteInternedString(kAttributeName));
  ASSERT_TRUE(writer_.WriteInt64(kAttributeValue));

  AndroidBinaryXmlTokenizer tokenizer;
  ASSERT_TRUE(tokenizer.Init(test_file_path_));

  ASSERT_TRUE(tokenizer.Next());
  EXPECT_EQ(tokenizer.token(), Token::kAttribute);
  EXPECT_EQ(tokenizer.type(), Type::kLongHex);
  EXPECT_EQ(tokenizer.name(), kAttributeName);
  EXPECT_EQ(tokenizer.int_value(), kAttributeValue);
  EXPECT_FALSE(tokenizer.Next());
  EXPECT_TRUE(tokenizer.is_eof());
}

TEST_F(AndroidBinaryXmlTokenizerTest, BooleanTrueAttribute) {
  constexpr char kAttributeName[] = "foo";

  // This is foo="true" in text XML.
  ASSERT_TRUE(writer_.WriteToken(Token::kAttribute, Type::kBooleanTrue));
  ASSERT_TRUE(writer_.WriteInternedString(kAttributeName));

  AndroidBinaryXmlTokenizer tokenizer;
  ASSERT_TRUE(tokenizer.Init(test_file_path_));

  ASSERT_TRUE(tokenizer.Next());
  EXPECT_EQ(tokenizer.token(), Token::kAttribute);
  EXPECT_EQ(tokenizer.type(), Type::kBooleanTrue);
  EXPECT_EQ(tokenizer.name(), kAttributeName);
  EXPECT_FALSE(tokenizer.Next());
  EXPECT_TRUE(tokenizer.is_eof());
}

TEST_F(AndroidBinaryXmlTokenizerTest, BooleanFalseAttribute) {
  constexpr char kAttributeName[] = "foo";

  // This is foo="false" in text XML.
  ASSERT_TRUE(writer_.WriteToken(Token::kAttribute, Type::kBooleanFalse));
  ASSERT_TRUE(writer_.WriteInternedString(kAttributeName));

  AndroidBinaryXmlTokenizer tokenizer;
  ASSERT_TRUE(tokenizer.Init(test_file_path_));

  ASSERT_TRUE(tokenizer.Next());
  EXPECT_EQ(tokenizer.token(), Token::kAttribute);
  EXPECT_EQ(tokenizer.type(), Type::kBooleanFalse);
  EXPECT_EQ(tokenizer.name(), kAttributeName);
  EXPECT_FALSE(tokenizer.Next());
  EXPECT_TRUE(tokenizer.is_eof());
}

}  // namespace

}  // namespace arc
