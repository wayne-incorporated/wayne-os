// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_IPV4_ADDRESS_H_
#define NET_BASE_IPV4_ADDRESS_H_

#include <netinet/in.h>

#include <array>
#include <optional>
#include <ostream>
#include <string>
#include <utility>

#include "net-base/export.h"
#include "net-base/ip_address_utils.h"

namespace net_base {

// Represents an IPv4 address.
class NET_BASE_EXPORT IPv4Address {
 public:
  // The length in bytes of addresses.
  static constexpr size_t kAddressLength = sizeof(struct in_addr);
  // The type of the internal address data. The address is stored in network
  // order (i.e. big endian).
  using DataType = std::array<uint8_t, kAddressLength>;

  // Creates the IPv4Address from IPv4 dotted-decimal notation.
  // TODO(b/269983153): Add a fuzzer test for this method.
  static std::optional<IPv4Address> CreateFromString(
      const std::string& address_string);
  static std::optional<IPv4Address> CreateFromString(
      const char* address_string);

  // Creates the IPv4Address from the raw byte buffer. |bytes| points to the
  // front of the byte buffer, and |bytes_length| is the length of the buffer.
  // The caller should guarantee the data between [bytes, bytes + bytes_length)
  // is valid memory.
  // Returns std::nullopt if |bytes_length| is not the same as kAddressLength.
  static std::optional<IPv4Address> CreateFromBytes(const char* bytes,
                                                    size_t bytes_length) {
    return CreateFromBytes(reinterpret_cast<const uint8_t*>(bytes),
                           bytes_length);
  }
  static std::optional<IPv4Address> CreateFromBytes(const uint8_t* bytes,
                                                    size_t bytes_length);

  // Constructs an instance with the "0.0.0.0" address.
  constexpr IPv4Address() : data_(DataType{}) {}

  // Constructs an instance by bytes in network order.
  // i.e. |b0| is the MSB and |b3| is the LSB.
  constexpr IPv4Address(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3)
      : IPv4Address(DataType{b0, b1, b2, b3}) {}
  constexpr explicit IPv4Address(const DataType& data) : data_(data) {}

  explicit IPv4Address(const struct in_addr& addr);

  // Returns true if the address is "0.0.0.0".
  bool IsZero() const;

  // Compares the byte value of |data_| with |rhs|.
  bool operator==(const IPv4Address& rhs) const;
  bool operator!=(const IPv4Address& rhs) const;
  bool operator<(const IPv4Address& rhs) const;

  // Returns the internal data.
  const DataType& data() const { return data_; }

  // Returns the address in byte, stored in network order (i.e. big endian).
  std::string ToByteString() const;

  // Returns the address in the IPv4 dotted-decimal notation.
  std::string ToString() const;

  // Returns the address in the in_addr type.
  struct in_addr ToInAddr() const;

 private:
  // Stores the raw byte of address in network order.
  DataType data_;
};

NET_BASE_EXPORT std::ostream& operator<<(std::ostream& os,
                                         const IPv4Address& address);

// Represents the IPv4 CIDR, that contains a IPv4 address and a prefix length.
using IPv4CIDR = CIDR<IPv4Address>;

}  // namespace net_base
#endif  // NET_BASE_IPV4_ADDRESS_H_
