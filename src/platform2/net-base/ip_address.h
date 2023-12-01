// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_IP_ADDRESS_H_
#define NET_BASE_IP_ADDRESS_H_

#include <optional>
#include <string>
#include <variant>

#include "net-base/export.h"
#include "net-base/ipv4_address.h"
#include "net-base/ipv6_address.h"

namespace net_base {

// Represents the family of the IP protocol.
enum class NET_BASE_EXPORT IPFamily {
  kIPv4,
  kIPv6,
};

// Represents an family-agnostic IP address, either a IPv4 or a IPv6 address.
class NET_BASE_EXPORT IPAddress {
 public:
  // Creates the IPAddress from IPv4 dotted-decimal notation or IPv6 network
  // address format.
  static std::optional<IPAddress> CreateFromString(
      const std::string& address_string);
  static std::optional<IPAddress> CreateFromString(const char* address_string);

  // Creates the IPAddress from the raw byte buffer. |bytes| points to the
  // front of the byte buffer, and |bytes_length| is the length of the buffer.
  // The caller should guarantee the data between [bytes, bytes + bytes_length)
  // is valid memory.
  // Returns std::nullopt if |bytes_length| is not the same as
  // IPv4Address::kAddressLength or IPv6Address::kAddressLength.
  static std::optional<IPAddress> CreateFromBytes(const char* bytes,
                                                  size_t bytes_length) {
    return CreateFromBytes(reinterpret_cast<const uint8_t*>(bytes),
                           bytes_length);
  }
  static std::optional<IPAddress> CreateFromBytes(const uint8_t* bytes,
                                                  size_t bytes_length);

  explicit constexpr IPAddress(const IPv4Address& address)
      : address_(address) {}
  explicit constexpr IPAddress(const IPv6Address& address)
      : address_(address) {}

  // Compares with |rhs|. The comparation rule follows IPv4Address and
  // IPv6Address if the family of |rhs| is the same. Otherwise, the IPv4Address
  // is less than IPv6Address.
  bool operator==(const IPAddress& rhs) const;
  bool operator!=(const IPAddress& rhs) const;
  bool operator<(const IPAddress& rhs) const;

  // Returns the family of the IP address.
  IPFamily GetFamily() const;

  // Converts to the family-specific classes. Returns std::nullopt if the IP
  // family is not the same.
  std::optional<IPv4Address> ToIPv4Address() const;
  std::optional<IPv6Address> ToIPv6Address() const;

  // Returns the address in byte, stored in network order (i.e. big endian).
  std::string ToByteString() const;

  // Returns the address in the IPv4 dotted-decimal notation or IPv6 network
  // address format.
  std::string ToString() const;

 private:
  std::variant<IPv4Address, IPv6Address> address_;
};

NET_BASE_EXPORT std::ostream& operator<<(std::ostream& os,
                                         const IPAddress& address);

}  // namespace net_base
#endif  // NET_BASE_IP_ADDRESS_H_
