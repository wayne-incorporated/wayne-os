// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net-base/ip_address.h"

#include <algorithm>

namespace net_base {

// static
std::optional<IPAddress> IPAddress::CreateFromString(
    const std::string& address_string) {
  return CreateFromString(address_string.c_str());
}

// static
std::optional<IPAddress> IPAddress::CreateFromString(
    const char* address_string) {
  const auto ipv4 = IPv4Address::CreateFromString(address_string);
  if (ipv4) {
    return IPAddress(*ipv4);
  }

  const auto ipv6 = IPv6Address::CreateFromString(address_string);
  if (ipv6) {
    return IPAddress(*ipv6);
  }

  return std::nullopt;
}

// static
std::optional<IPAddress> IPAddress::CreateFromBytes(const uint8_t* bytes,
                                                    size_t byte_length) {
  const auto ipv4 = IPv4Address::CreateFromBytes(bytes, byte_length);
  if (ipv4) {
    return IPAddress(*ipv4);
  }

  const auto ipv6 = IPv6Address::CreateFromBytes(bytes, byte_length);
  if (ipv6) {
    return IPAddress(*ipv6);
  }

  return std::nullopt;
}

bool IPAddress::operator==(const IPAddress& rhs) const {
  return address_ == rhs.address_;
}

bool IPAddress::operator!=(const IPAddress& rhs) const {
  return !(*this == rhs);
}

bool IPAddress::operator<(const IPAddress& rhs) const {
  return address_ < rhs.address_;
}

IPFamily IPAddress::GetFamily() const {
  if (const auto ipv4 = std::get_if<IPv4Address>(&address_)) {
    return IPFamily::kIPv4;
  }
  return IPFamily::kIPv6;
}

std::optional<IPv4Address> IPAddress::ToIPv4Address() const {
  if (const auto ipv4 = std::get_if<IPv4Address>(&address_)) {
    return *ipv4;
  }
  return std::nullopt;
}

std::optional<IPv6Address> IPAddress::ToIPv6Address() const {
  if (const auto ipv6 = std::get_if<IPv6Address>(&address_)) {
    return *ipv6;
  }
  return std::nullopt;
}

std::string IPAddress::ToByteString() const {
  return std::visit(
      [](auto&& address) -> std::string { return address.ToByteString(); },
      address_);
}

std::string IPAddress::ToString() const {
  return std::visit(
      [](auto&& address) -> std::string { return address.ToString(); },
      address_);
}

std::ostream& operator<<(std::ostream& os, const IPAddress& address) {
  os << address.ToString();
  return os;
}

}  // namespace net_base
