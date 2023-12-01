// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net-base/ipv6_address.h"

#include <algorithm>

#include <arpa/inet.h>

#include <base/check.h>

namespace net_base {

// static
std::optional<IPv6Address> IPv6Address::CreateFromString(
    const std::string& address_string) {
  return CreateFromString(address_string.c_str());
}

// static
std::optional<IPv6Address> IPv6Address::CreateFromString(
    const char* address_string) {
  DataType data;
  if (inet_pton(AF_INET6, address_string, data.data()) <= 0) {
    return std::nullopt;
  }
  return IPv6Address(data);
}

// static
std::optional<IPv6Address> IPv6Address::CreateFromBytes(const uint8_t* bytes,
                                                        size_t byte_length) {
  return CreateAddressFromBytes<IPv6Address>(bytes, byte_length);
}

IPv6Address::IPv6Address(const struct in6_addr& addr) {
  std::copy_n(reinterpret_cast<const uint8_t*>(&addr), kAddressLength,
              data_.begin());
}

bool IPv6Address::IsZero() const {
  return std::all_of(data_.begin(), data_.end(),
                     [](uint8_t byte) { return byte == 0; });
}

bool IPv6Address::operator==(const IPv6Address& rhs) const {
  return data_ == rhs.data_;
}

bool IPv6Address::operator!=(const IPv6Address& rhs) const {
  return !(*this == rhs);
}

bool IPv6Address::operator<(const IPv6Address& rhs) const {
  return data_ < rhs.data_;
}

std::string IPv6Address::ToByteString() const {
  return {reinterpret_cast<const char*>(data_.data()), kAddressLength};
}

struct in6_addr IPv6Address::ToIn6Addr() const {
  struct in6_addr ret;
  memcpy(&ret, data_.data(), kAddressLength);
  return ret;
}

std::string IPv6Address::ToString() const {
  char address_buf[INET6_ADDRSTRLEN];
  const char* res =
      inet_ntop(AF_INET6, data_.data(), address_buf, sizeof(address_buf));
  DCHECK(res);
  return std::string(address_buf);
}

std::ostream& operator<<(std::ostream& os, const IPv6Address& address) {
  os << address.ToString();
  return os;
}

}  // namespace net_base
