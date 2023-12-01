// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_SECURE_BLOB_H_
#define LIBBRILLO_BRILLO_SECURE_BLOB_H_

#include <initializer_list>
#include <string>
#include <vector>

#include <brillo/asan.h>
#include <brillo/brillo_export.h>
#include <brillo/secure_allocator.h>

namespace brillo {

using Blob = std::vector<uint8_t>;

// Define types based on the SecureAllocator for instantiation.
// ------------------------------------------------------------
// Define SecureVector as a vector using a SecureAllocator.
// Over time, the goal is to remove the differentiating functions
// from SecureBlob (to_string(), char_data()) till it converges with
// SecureVector.
using SecureVector = std::vector<uint8_t, SecureAllocator<uint8_t>>;

// Conversion of Blob to/from std::string, where the string holds raw byte
// contents.
BRILLO_EXPORT std::string BlobToString(const Blob& blob);
BRILLO_EXPORT Blob BlobFromString(const std::string& bytes);

// Returns a concatenation of given Blobs.
BRILLO_EXPORT Blob CombineBlobs(const std::initializer_list<Blob>& blobs);

// SecureBlob erases the contents on destruction.  It does not guarantee erasure
// on resize, assign, etc.
class BRILLO_EXPORT SecureBlob : public SecureVector {
 public:
  SecureBlob() = default;
  // Inherit standard constructors from SecureVector.
  using SecureVector::vector;
  explicit SecureBlob(const Blob& blob);
  explicit SecureBlob(const std::string& data);
  ~SecureBlob();

  void resize(size_type count);
  void resize(size_type count, const value_type& value);
  void clear();

  std::string to_string() const;
  char* char_data() { return reinterpret_cast<char*>(data()); }
  const char* char_data() const {
    return reinterpret_cast<const char*>(data());
  }
  static SecureBlob Combine(const SecureBlob& blob1, const SecureBlob& blob2);
  static bool HexStringToSecureBlob(const std::string& input,
                                    SecureBlob* output);
};

// Conversion of SecureBlob data to/from SecureBlob hex. This is useful
// for sensitive data like encryption keys, that should, in the ideal case never
// be exposed as strings in the first place. In case the existing data or hex
// string is already exposed as a std::string, it is preferable to use the
// BlobToString variant.
BRILLO_EXPORT SecureBlob SecureBlobToSecureHex(const SecureBlob& blob);
BRILLO_EXPORT SecureBlob SecureHexToSecureBlob(const SecureBlob& hex);

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_SECURE_BLOB_H_
