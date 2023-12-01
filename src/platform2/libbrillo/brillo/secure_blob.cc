// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstring>  // memcpy

#include <base/stl_util.h>
#include <base/strings/string_number_conversions.h>

#include "brillo/secure_blob.h"
#include "brillo/secure_string.h"

namespace brillo {

namespace {

bool ConvertHexToBytes(char c, uint8_t* v) {
  if (c >= '0' && c <= '9')
    *v = c - '0';
  else if (c >= 'a' && c <= 'f')
    *v = c - 'a' + 10;
  else if (c >= 'A' && c <= 'F')
    *v = c - 'A' + 10;
  else
    return false;

  return true;
}

}  // namespace

std::string BlobToString(const Blob& blob) {
  return std::string(blob.begin(), blob.end());
}

Blob BlobFromString(const std::string& bytes) {
  return Blob(bytes.begin(), bytes.end());
}

Blob CombineBlobs(const std::initializer_list<Blob>& blobs) {
  size_t total_size = 0;
  for (const auto& blob : blobs)
    total_size += blob.size();
  Blob concatenation;
  concatenation.reserve(total_size);
  for (const auto& blob : blobs)
    concatenation.insert(concatenation.end(), blob.begin(), blob.end());
  return concatenation;
}

SecureBlob::SecureBlob(const Blob& blob)
    : SecureBlob(blob.begin(), blob.end()) {}

SecureBlob::SecureBlob(const std::string& data)
    : SecureBlob(data.begin(), data.end()) {}

SecureBlob::~SecureBlob() {
  SecureVector::clear();
}

void SecureBlob::resize(size_type count) {
  if (count < size()) {
    SecureClearBytes(data() + count, capacity() - count);
  }
  SecureVector::resize(count);
}

void SecureBlob::resize(size_type count, const value_type& value) {
  if (count < size()) {
    SecureClearBytes(data() + count, capacity() - count);
  }
  SecureVector::resize(count, value);
}

void SecureBlob::clear() {
  SecureVector::clear();
}

std::string SecureBlob::to_string() const {
  return std::string(data(), data() + size());
}

SecureBlob SecureBlob::Combine(const SecureBlob& blob1,
                               const SecureBlob& blob2) {
  SecureBlob result;
  result.reserve(blob1.size() + blob2.size());
  result.insert(result.end(), blob1.begin(), blob1.end());
  result.insert(result.end(), blob2.begin(), blob2.end());
  return result;
}

bool SecureBlob::HexStringToSecureBlob(const std::string& input,
                                       SecureBlob* output) {
  // TODO(jorgelo,crbug.com/728047): Consider not using an intermediate
  // std::vector here at all.
  std::vector<uint8_t> temp;
  if (!base::HexStringToBytes(input, &temp)) {
    output->clear();
    return false;
  }
  output->assign(temp.begin(), temp.end());
  SecureClearBytes(temp.data(), temp.capacity());
  return true;
}

// base::HexEncode and base::HexStringToBytes use strings, which may leak
// contents. These functions are alternatives that keep all contents
// within secured memory.
SecureBlob SecureBlobToSecureHex(const SecureBlob& blob) {
  std::string kHexChars("0123456789ABCDEF");
  SecureBlob hex(blob.size() * 2, 0);
  const char* blob_char_data = blob.char_data();

  // Each input byte creates two output hex characters.
  for (size_t i = 0; i < blob.size(); ++i) {
    hex[(i * 2)] = kHexChars[(blob_char_data[i] >> 4) & 0xf];
    hex[(i * 2) + 1] = kHexChars[blob_char_data[i] & 0xf];
  }
  return hex;
}

SecureBlob SecureHexToSecureBlob(const SecureBlob& hex) {
  SecureBlob blob(hex.size() / 2, 0);

  if (hex.size() == 0 || hex.size() % 2)
    return SecureBlob();

  for (size_t i = 0; i < hex.size(); i++) {
    uint8_t v;
    // Check for invalid characters.
    if (!ConvertHexToBytes(hex[i], &v))
      return SecureBlob();

    blob[i / 2] = (blob[i / 2] << 4) | (v & 0xf);
  }

  return blob;
}

}  // namespace brillo
