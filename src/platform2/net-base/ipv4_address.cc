// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net-base/ipv4_address.h"

#include <algorithm>

#include <arpa/inet.h>

#include <base/check.h>
#include <base/sys_byteorder.h>

namespace net_base {

// static
std::optional<IPv4Address> IPv4Address::CreateFromString(
    const std::string& address_string) {
  return CreateFromString(address_string.c_str());
}

// static
std::optional<IPv4Address> IPv4Address::CreateFromString(
    const char* address_string) {
  DataType data;
  if (inet_pton(AF_INET, address_string, data.data()) <= 0) {
    return std::nullopt;
  }
  return IPv4Address(data);
}

// static
std::optional<IPv4Address> IPv4Address::CreateFromBytes(const uint8_t* bytes,
                                                        size_t byte_length) {
  return CreateAddressFromBytes<IPv4Address>(bytes, byte_length);
}

IPv4Address::IPv4Address(const struct in_addr& addr) {
  const uint32_t host_endian = base::NetToHost32(addr.s_addr);
  data_[0] = static_cast<uint8_t>((host_endian >> 24) & 0xff);
  data_[1] = static_cast<uint8_t>((host_endian >> 16) & 0xff);
  data_[2] = static_cast<uint8_t>((host_endian >> 8) & 0xff);
  data_[3] = static_cast<uint8_t>(host_endian & 0xff);
}

bool IPv4Address::IsZero() const {
  return std::all_of(data_.begin(), data_.end(),
                     [](uint8_t byte) { return byte == 0; });
}

bool IPv4Address::operator==(const IPv4Address& rhs) const {
  return data_ == rhs.data_;
}

bool IPv4Address::operator!=(const IPv4Address& rhs) const {
  return !(*this == rhs);
}

bool IPv4Address::operator<(const IPv4Address& rhs) const {
  return data_ < rhs.data_;
}

std::string IPv4Address::ToByteString() const {
  return {reinterpret_cast<const char*>(data_.data()), kAddressLength};
}

std::string IPv4Address::ToString() const {
  char address_buf[INET_ADDRSTRLEN];
  const char* res =
      inet_ntop(AF_INET, data_.data(), address_buf, sizeof(address_buf));
  DCHECK(res);
  return std::string(address_buf);
}

struct in_addr IPv4Address::ToInAddr() const {
  const uint32_t host_endian = (static_cast<uint32_t>(data_[0]) << 24) |
                               (static_cast<uint32_t>(data_[1]) << 16) |
                               (static_cast<uint32_t>(data_[2]) << 8) |
                               static_cast<uint32_t>(data_[3]);

  struct in_addr ret;
  ret.s_addr = htonl(host_endian);
  return ret;
}

std::ostream& operator<<(std::ostream& os, const IPv4Address& address) {
  os << address.ToString();
  return os;
}

}  // namespace net_base
