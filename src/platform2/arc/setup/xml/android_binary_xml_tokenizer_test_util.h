// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_SETUP_XML_ANDROID_BINARY_XML_TOKENIZER_TEST_UTIL_H_
#define ARC_SETUP_XML_ANDROID_BINARY_XML_TOKENIZER_TEST_UTIL_H_

#include <map>
#include <string>

#include "arc/setup/xml/android_binary_xml_tokenizer.h"
#include "base/files/file.h"

namespace arc {

// AndroidBinaryXmlWriter writes Android binary XML tokens to a file.
class AndroidBinaryXmlWriter {
 public:
  using Token = AndroidBinaryXmlTokenizer::Token;
  using Type = AndroidBinaryXmlTokenizer::Type;

  AndroidBinaryXmlWriter();
  ~AndroidBinaryXmlWriter();
  AndroidBinaryXmlWriter(const AndroidBinaryXmlWriter&) = delete;
  AndroidBinaryXmlWriter& operator=(const AndroidBinaryXmlWriter&) = delete;

  // Initializes this object.
  bool Init(const base::FilePath& path);

  // Writes the specified data to the test file.
  bool WriteData(const void* buf, size_t size);

  // Writes a token byte to the test file.
  bool WriteToken(Token token, Type type);

  // Writes a uint16 to the test file.
  bool WriteUint16(uint16_t value);

  // Writes an int32 to the test file.
  bool WriteInt32(int32_t value);

  // Writes an int64 to the test file.
  bool WriteInt64(int64_t value);

  // Writes a string to the test file.
  bool WriteString(const std::string& value);

  // Writes an interned string to the test file.
  bool WriteInternedString(const std::string& value);

 private:
  base::File file_;

  // Map from interned string to index.
  std::map<std::string, int> interned_strings_;
};

}  // namespace arc

#endif  // ARC_SETUP_XML_ANDROID_BINARY_XML_TOKENIZER_TEST_UTIL_H_
