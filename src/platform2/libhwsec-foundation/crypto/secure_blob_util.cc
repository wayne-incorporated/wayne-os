// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/crypto/secure_blob_util.h"

#include <string>

#include <base/check_op.h>
#include <base/numerics/safe_conversions.h>
#include <openssl/rand.h>

namespace hwsec_foundation {

namespace {

template <class T>
void BlobToHexToBufferHelper(const T& data,
                             void* buffer,
                             size_t buffer_length) {
  static const char table[] = "0123456789abcdef";
  char* char_buffer = reinterpret_cast<char*>(buffer);
  char* char_buffer_end = char_buffer + buffer_length;
  for (uint8_t byte : data) {
    if (char_buffer == char_buffer_end)
      break;
    *char_buffer++ = table[(byte >> 4) & 0x0f];
    if (char_buffer == char_buffer_end)
      break;
    *char_buffer++ = table[byte & 0x0f];
  }
  if (char_buffer != char_buffer_end)
    *char_buffer = '\x00';
}

}  // namespace

void GetSecureRandom(unsigned char* buf, size_t length) {
  // In unlikely situations, such as the random generator lacks enough entropy,
  // RAND_bytes can fail.
  CHECK_EQ(1, RAND_bytes(buf, base::checked_cast<int>(length)));
}

brillo::SecureBlob CreateSecureRandomBlob(size_t length) {
  brillo::SecureBlob blob(length);
  GetSecureRandom(reinterpret_cast<unsigned char*>(blob.data()), length);
  return blob;
}

std::string BlobToHex(const brillo::Blob& blob) {
  std::string buffer(blob.size() * 2, '\x00');
  BlobToHexToBuffer(blob, &buffer[0], buffer.size());
  return buffer;
}

std::string SecureBlobToHex(const brillo::SecureBlob& blob) {
  std::string buffer(blob.size() * 2, '\x00');
  SecureBlobToHexToBuffer(blob, &buffer[0], buffer.size());
  return buffer;
}

void BlobToHexToBuffer(const brillo::Blob& blob,
                       void* buffer,
                       size_t buffer_length) {
  BlobToHexToBufferHelper(blob, buffer, buffer_length);
}

void SecureBlobToHexToBuffer(const brillo::SecureBlob& blob,
                             void* buffer,
                             size_t buffer_length) {
  BlobToHexToBufferHelper(blob, buffer, buffer_length);
}

}  // namespace hwsec_foundation
