// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NET_BYTE_STRING_H_
#define SHILL_NET_BYTE_STRING_H_

#include <string>
#include <vector>

#include "shill/net/shill_export.h"

namespace shill {

// Holder of a vector of bytes that can be manipulated both as a string and as a
// contiguous array of unsigned chars.
// Is both copyable and movable.
class SHILL_EXPORT ByteString {
 public:
  ByteString() = default;

  explicit ByteString(const std::vector<unsigned char>& data) : data_(data) {}

  explicit ByteString(size_t length) : data_(length) {}

  ByteString(const unsigned char* data, size_t length)
      : data_(data, data + length) {}

  ByteString(const char* data, size_t length) : data_(data, data + length) {}

  ByteString(const signed char* data, size_t length)
      : data_(data, data + length) {}

  ByteString(const std::string& data, bool copy_terminator)
      : data_(reinterpret_cast<const unsigned char*>(data.c_str()),
              reinterpret_cast<const unsigned char*>(
                  data.c_str() + data.length() + (copy_terminator ? 1 : 0))) {}

  unsigned char* GetData();
  const unsigned char* GetConstData() const;
  const char* GetConstCString() const;
  size_t GetLength() const;

  // Returns a ByteString containing |length| bytes from the ByteString
  // starting at |offset|.  This function truncates the returned string
  // if part (or all) of this requested data lies outside the bounds of
  // this ByteString.
  ByteString GetSubstring(size_t offset, size_t length) const;

  // Inserts a uint32_t into a ByteString in cpu-order
  static ByteString CreateFromCPUUInt32(uint32_t val);
  // Inserts a uint32_t into a ByteString in network-order
  static ByteString CreateFromNetUInt32(uint32_t val);

  // Creates a ByteString from a string of hexadecimal digits where
  // a pair of hexadecimal digits corresponds to a byte.
  // Returns a default-constructed ByteString if |hex_string| is empty
  // or not a valid string of hexadecimal digits representing a sequence
  // of bytes.
  static ByteString CreateFromHexString(const std::string& hex_string);

  // Converts to a uint32_t from a host-order value stored in the ByteString
  // Returns true on success
  bool ConvertToCPUUInt32(uint32_t* val) const;
  // Converts to a uint32_t from a network-order value stored in the ByteString
  // Returns true on success
  bool ConvertToNetUInt32(uint32_t* val) const;

  // Converts the string of bytes stored in the ByteString from network order
  // to host order in 32-bit chunks. Returns true on success or false if the
  // length of ByteString is not a multiple of 4.
  bool ConvertFromNetToCPUUInt32Array();

  // Converts the string of bytes stored in the ByteString from host order
  // to network order in 32-bit chunks. Returns true on success or false if the
  // length of ByteString is not a multiple of 4.
  bool ConvertFromCPUToNetUInt32Array();

  bool IsEmpty() const { return GetLength() == 0; }

  // Returns true if every element of |this| is zero, false otherwise.
  bool IsZero() const;

  // Perform an AND operation between each element of |this| with the
  // corresponding byte of |b|.  Returns true if both |this| and |b|
  // are the same length, and as such the operation succeeds; false
  // if they are not.  The result of the operation is stored in |this|.
  bool BitwiseAnd(const ByteString& b);

  // Perform an OR operation between each element of |this| with the
  // corresponding byte of |b|.  Returns true if both |this| and |b|
  // are the same length, and as such the operation succeeds; false
  // if they are not.  The result of the operation is stored in |this|.
  bool BitwiseOr(const ByteString& b);

  // Perform an inversion operation on each of the bits this string.
  void BitwiseInvert();

  bool Equals(const ByteString& b) const;
  bool operator==(const ByteString& b) const { return Equals(b); }
  void Append(const ByteString& b);
  void Clear();
  void Resize(int size);

  std::string HexEncode() const;

  // Ensures that |size| bytes are available in the payload, then copies
  // these bytes to |output|.  Returns false if |this| does not contain enough
  // data.
  bool CopyData(size_t size, void* output) const;

  static bool IsLessThan(const ByteString& lhs, const ByteString& rhs);

  bool operator<(const ByteString& b) const { return IsLessThan(*this, b); }

 private:
  // Converts the string of bytes stored in the ByteString by treating it as
  // an array of unsigned integer of type T and applying |converter| on each
  // unsigned value of type T. Return true on success or false if the length
  // ByteString is not a multiple of sizeof(T).
  template <typename T>
  bool ConvertByteOrderAsUIntArray(T (*converter)(T));

  std::vector<unsigned char> data_;
};

}  // namespace shill

#endif  // SHILL_NET_BYTE_STRING_H_
