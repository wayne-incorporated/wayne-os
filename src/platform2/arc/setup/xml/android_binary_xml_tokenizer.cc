// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/setup/xml/android_binary_xml_tokenizer.h"

#include <base/logging.h>
#include <endian.h>

namespace arc {

// The first four bytes of an Android binary XML are the magic number 'ABX_'.
// The fourth byte is the version number which should be 0.
//
// static
const char AndroidBinaryXmlTokenizer::kMagicNumber[4] = {'A', 'B', 'X', 0};

AndroidBinaryXmlTokenizer::AndroidBinaryXmlTokenizer() = default;

AndroidBinaryXmlTokenizer::~AndroidBinaryXmlTokenizer() = default;

bool AndroidBinaryXmlTokenizer::Init(const base::FilePath& path) {
  file_.Initialize(path, base::File::FLAG_OPEN | base::File::FLAG_READ);
  if (!file_.IsValid()) {
    LOG(ERROR) << "Failed to initialize the file: " << path
               << ", error = " << file_.error_details();
    return false;
  }
  // Check the magic number.
  char buf[sizeof(kMagicNumber)] = {};
  if (file_.ReadAtCurrentPos(buf, sizeof(buf)) != sizeof(buf) ||
      memcmp(buf, kMagicNumber, sizeof(kMagicNumber)) != 0) {
    LOG(ERROR) << "Invalid magic number";
    return false;
  }
  return true;
}

bool AndroidBinaryXmlTokenizer::Next() {
  // Read the token.
  uint8_t value = 0;
  int result =
      file_.ReadAtCurrentPos(reinterpret_cast<char*>(&value), sizeof(value));
  if (result == 0) {  // Reached EOF.
    is_eof_ = true;
    return false;
  } else if (result != sizeof(value)) {  // Failed to read.
    LOG(ERROR) << "Failed to read the token at " << GetPosition();
    return false;
  }

  // Reset fields.
  name_.clear();
  string_value_.clear();
  int_value_ = 0;
  bytes_value_.clear();

  // The lower four bits indicate the token type.
  token_ = static_cast<Token>(value & 0x0f);
  // The upper four bits indicate the data type.
  type_ = static_cast<Type>((value & 0xf0) >> 4);
  switch (token_) {
    case Token::kStartDocument:
      return true;

    case Token::kEndDocument:
      return true;

    case Token::kStartTag: {
      std::optional<std::string> name = ConsumeInternedString();
      if (!name) {
        LOG(ERROR) << "Failed to read the tag name at " << GetPosition();
        return false;
      }
      name_ = *name;
      ++depth_;
      return true;
    }
    case Token::kEndTag: {
      std::optional<std::string> name = ConsumeInternedString();
      if (!name) {
        LOG(ERROR) << "Failed to read the tag name at " << GetPosition();
        return false;
      }
      name_ = *name;
      --depth_;
      return true;
    }
    case Token::kAttribute: {
      std::optional<std::string> name = ConsumeInternedString();
      if (!name) {
        LOG(ERROR) << "Failed to read the attribute name.";
        return false;
      }
      name_ = *name;

      switch (type_) {
        case Type::kNull:
        case Type::kBooleanTrue:
        case Type::kBooleanFalse:
          return true;

        case Type::kString: {
          std::optional<std::string> value = ConsumeString();
          if (!value) {
            LOG(ERROR) << "Failed to read the attribute value of " << *name;
            return false;
          }
          string_value_ = *value;
          return true;
        }
        case Type::kStringInterned: {
          std::optional<std::string> value = ConsumeInternedString();
          if (!value) {
            LOG(ERROR) << "Failed to read the attribute value of " << *name;
            return false;
          }
          string_value_ = *value;
          return true;
        }
        case Type::kBytesHex:
        case Type::kBytesBase64: {
          std::optional<uint16_t> length = ConsumeUint16();
          if (!length) {
            LOG(ERROR) << "Failed to read the attribute length of " << *name;
            return false;
          }
          bytes_value_.resize(*length);
          if (file_.ReadAtCurrentPos(
                  reinterpret_cast<char*>(bytes_value_.data()),
                  bytes_value_.size()) != bytes_value_.size()) {
            LOG(ERROR) << "Failed to read the attribute value of " << *name;
            return false;
          }
          return true;
        }
        case Type::kInt:
        case Type::kIntHex: {
          std::optional<int32_t> value = ConsumeInt32();
          if (!value) {
            LOG(ERROR) << "Failed to read the attribute value of " << *name;
            return false;
          }
          int_value_ = *value;
          return true;
        }
        case Type::kLong:
        case Type::kLongHex: {
          std::optional<int64_t> value = ConsumeInt64();
          if (!value) {
            LOG(ERROR) << "Failed to read the attribute value of " << *name;
            return false;
          }
          int_value_ = *value;
          return true;
        }
      }
      LOG(ERROR) << "Unexpected attribute type " << static_cast<int>(type_);
      return false;
    }
  }
  LOG(ERROR) << "Unexpected token " << static_cast<int>(token_) << " at "
             << GetPosition();
  return false;
}

int64_t AndroidBinaryXmlTokenizer::GetPosition() {
  return file_.Seek(base::File::Whence::FROM_CURRENT, 0);
}

std::optional<uint16_t> AndroidBinaryXmlTokenizer::ConsumeUint16() {
  uint16_t value = 0;
  if (file_.ReadAtCurrentPos(reinterpret_cast<char*>(&value), sizeof(value)) !=
      sizeof(value)) {
    return {};
  }
  return be16toh(value);
}

std::optional<int32_t> AndroidBinaryXmlTokenizer::ConsumeInt32() {
  uint32_t value = 0;
  if (file_.ReadAtCurrentPos(reinterpret_cast<char*>(&value), sizeof(value)) !=
      sizeof(value)) {
    return {};
  }
  return be32toh(value);
}

std::optional<int64_t> AndroidBinaryXmlTokenizer::ConsumeInt64() {
  uint64_t value = 0;
  if (file_.ReadAtCurrentPos(reinterpret_cast<char*>(&value), sizeof(value)) !=
      sizeof(value)) {
    return {};
  }
  return be64toh(value);
}

std::optional<std::string> AndroidBinaryXmlTokenizer::ConsumeString() {
  std::optional<uint16_t> length = ConsumeUint16();
  if (!length) {
    return {};
  }
  std::string data(*length, 0);
  if (file_.ReadAtCurrentPos(data.data(), data.size()) != data.size()) {
    return {};
  }
  return data;
}

std::optional<std::string> AndroidBinaryXmlTokenizer::ConsumeInternedString() {
  // An interned string is a string which is represented by an index.
  std::optional<uint16_t> index = ConsumeUint16();
  if (!index) {
    return {};
  }
  // index != 0xffff means this string was already interned.
  if (*index != 0xffff) {
    if (*index >= interned_strings_.size()) {
      return {};
    }
    return interned_strings_[*index];
  }
  // index == 0xffff means this is the first appearance of the string.
  std::optional<std::string> data = ConsumeString();
  if (!data) {
    return {};
  }
  // Intern the string.
  interned_strings_.push_back(*data);
  return data;
}

}  // namespace arc
