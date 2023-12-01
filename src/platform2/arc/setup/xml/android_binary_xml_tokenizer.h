// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_SETUP_XML_ANDROID_BINARY_XML_TOKENIZER_H_
#define ARC_SETUP_XML_ANDROID_BINARY_XML_TOKENIZER_H_

#include <optional>
#include <string>
#include <vector>

#include <base/component_export.h>
#include <base/files/file.h>
#include <base/files/file_path.h>

namespace arc {

// Tokenizer for the Android Binary XML.
// The format is defined by the implementation of Android's
// frameworks/base/core/java/com/android/internal/util/BinaryXmlSerializer.java
// and BinaryXmlPullParser.java.
class COMPONENT_EXPORT(LIBANDROIDXML) AndroidBinaryXmlTokenizer {
 public:
  // Token constants are defined in Android's
  // libcore/xml/src/main/java/org/xmlpull/v1/XmlPullParser.java
  enum class Token {
    kStartDocument = 0,
    kEndDocument = 1,
    kStartTag = 2,
    kEndTag = 3,

    // This value is defined in Android's BinaryXmlSerializer.java.
    kAttribute = 15,
  };

  // Type constants are defined in Android's BinaryXmlSerializer.java.
  enum class Type {
    kNull = 1,
    kString = 2,
    kStringInterned = 3,
    kBytesHex = 4,
    kBytesBase64 = 5,
    kInt = 6,
    kIntHex = 7,
    kLong = 8,
    kLongHex = 9,
    // Float and double are not supported because they don't appear in
    // packages.xml.
    // TODO(hashimoto): Handle these types when it becomes necessary.
    // kFloat = 10,
    // kDouble = 11,
    kBooleanTrue = 12,
    kBooleanFalse = 13,
  };

  static const char kMagicNumber[4];

  AndroidBinaryXmlTokenizer();
  AndroidBinaryXmlTokenizer(const AndroidBinaryXmlTokenizer&) = delete;
  const AndroidBinaryXmlTokenizer& operator=(const AndroidBinaryXmlTokenizer&) =
      delete;
  ~AndroidBinaryXmlTokenizer();

  // Initializes this object to read the specified file.
  bool Init(const base::FilePath& path);

  // Moves to the next token.
  bool Next();

  // Returns true after reaching EOF.
  bool is_eof() const { return is_eof_; }

  // The type of the current token.
  Token token() const { return token_; }

  // The data type of the current token.
  Type type() const { return type_; }

  // The depth of the current token.
  int depth() const { return depth_; }

  // The name of the current token.
  const std::string& name() const { return name_; }

  // Value of the current token.
  // Check type() to know which value is the valid one.
  const std::string& string_value() const { return string_value_; }
  int64_t int_value() const { return int_value_; }
  const std::vector<uint8_t>& bytes_value() const { return bytes_value_; }

 private:
  // Returns the current read position of the file.
  int64_t GetPosition();

  // Consumes the file contents and returns data.
  std::optional<uint16_t> ConsumeUint16();
  std::optional<int32_t> ConsumeInt32();
  std::optional<int64_t> ConsumeInt64();
  std::optional<std::string> ConsumeString();
  std::optional<std::string> ConsumeInternedString();

  // The binary XML file being read.
  base::File file_;

  std::vector<std::string> interned_strings_;

  bool is_eof_ = false;

  Token token_ = Token::kStartDocument;
  Type type_ = Type::kNull;
  int depth_ = 0;
  std::string name_;
  std::string string_value_;
  int64_t int_value_ = 0;
  std::vector<uint8_t> bytes_value_;
};

}  // namespace arc

#endif  // ARC_SETUP_XML_ANDROID_BINARY_XML_TOKENIZER_H_
