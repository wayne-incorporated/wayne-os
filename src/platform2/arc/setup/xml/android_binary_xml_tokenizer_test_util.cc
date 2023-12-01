// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/setup/xml/android_binary_xml_tokenizer_test_util.h"

#include "base/logging.h"

namespace arc {

AndroidBinaryXmlWriter::AndroidBinaryXmlWriter() = default;
AndroidBinaryXmlWriter::~AndroidBinaryXmlWriter() = default;

bool AndroidBinaryXmlWriter::Init(const base::FilePath& path) {
  file_.Initialize(path, base::File::FLAG_CREATE | base::File::FLAG_WRITE);
  if (!file_.IsValid()) {
    LOG(ERROR) << "Failed to initialize the file.";
    return false;
  }
  // Write the magic number to the file.
  if (!WriteData(AndroidBinaryXmlTokenizer::kMagicNumber,
                 sizeof(AndroidBinaryXmlTokenizer::kMagicNumber))) {
    LOG(ERROR) << "Failed to write the magic number.";
    return false;
  }
  return true;
}

bool AndroidBinaryXmlWriter::WriteData(const void* buf, size_t size) {
  return file_.WriteAtCurrentPos(static_cast<const char*>(buf), size) == size;
}

bool AndroidBinaryXmlWriter::WriteToken(Token token, Type type) {
  const char buf = static_cast<int>(token) | (static_cast<int>(type) << 4);
  return WriteData(&buf, sizeof(buf));
}

bool AndroidBinaryXmlWriter::WriteUint16(uint16_t value) {
  const uint16_t buf = htobe16(value);
  return WriteData(&buf, sizeof(buf));
}

bool AndroidBinaryXmlWriter::WriteInt32(int32_t value) {
  const uint32_t buf = htobe32(value);
  return WriteData(&buf, sizeof(buf));
}

bool AndroidBinaryXmlWriter::WriteInt64(int64_t value) {
  const uint64_t buf = htobe64(value);
  return WriteData(&buf, sizeof(buf));
}

bool AndroidBinaryXmlWriter::WriteString(const std::string& value) {
  return WriteUint16(value.size()) && WriteData(value.data(), value.size());
}

bool AndroidBinaryXmlWriter::WriteInternedString(const std::string& value) {
  auto it = interned_strings_.find(value);
  if (it != interned_strings_.end()) {
    return WriteUint16(it->second);
  }
  const size_t index = interned_strings_.size();
  interned_strings_[value] = index;
  return WriteUint16(0xffff) && WriteString(value);
}

}  // namespace arc
