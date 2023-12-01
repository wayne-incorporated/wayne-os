// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/net/ip_address.h"

#include <arpa/inet.h>

#include <limits>
#include <optional>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>

namespace shill {

namespace {
using net_base::IPv4Address;
using net_base::IPv4CIDR;
using net_base::IPv6Address;
using net_base::IPv6CIDR;

const size_t kBitsPerByte = 8;
}  // namespace

// static
const char IPAddress::kFamilyNameUnknown[] = "Unknown";
// static
const char IPAddress::kFamilyNameIPv4[] = "IPv4";
// static
const char IPAddress::kFamilyNameIPv6[] = "IPv6";

// static
IPAddress IPAddress::CreateFromFamily(Family family) {
  switch (family) {
    case kFamilyIPv4:
      return IPAddress(IPv4Address());
    case kFamilyIPv6:
      return IPAddress(IPv6Address());
    default:
      return IPAddress(kFamilyUnknown, ByteString());
  }
}

// static
IPAddress IPAddress::CreateFromFamily_Deprecated(Family family) {
  return IPAddress(family, ByteString(), 0);
}

IPAddress::IPAddress(Family family, const ByteString& address)
    : IPAddress(family, address, 0) {}

IPAddress::IPAddress(Family family,
                     const ByteString& address,
                     unsigned int prefix)
    : family_(family), address_(address), prefix_(prefix) {}

IPAddress::IPAddress(const IPv4Address& address)
    : family_(kFamilyIPv4),
      address_({address.ToByteString(), false}),
      prefix_(0) {}

IPAddress::IPAddress(const IPv6Address& address)
    : family_(kFamilyIPv6),
      address_({address.ToByteString(), false}),
      prefix_(0) {}

IPAddress::IPAddress(const IPv4CIDR& cidr)
    : family_(kFamilyIPv4),
      address_({cidr.address().ToByteString(), false}),
      prefix_(cidr.prefix_length()) {}

IPAddress::IPAddress(const IPv6CIDR& cidr)
    : family_(kFamilyIPv6),
      address_({cidr.address().ToByteString(), false}),
      prefix_(cidr.prefix_length()) {}

IPAddress::~IPAddress() = default;

// static
size_t IPAddress::GetAddressLength(Family family) {
  switch (family) {
    case kFamilyIPv4:
      return sizeof(in_addr);
    case kFamilyIPv6:
      return sizeof(in6_addr);
    default:
      return 0;
  }
}

// static
size_t IPAddress::GetMaxPrefixLength(Family family) {
  return GetAddressLength(family) * kBitsPerByte;
}

// static
size_t IPAddress::GetPrefixLengthFromMask(Family family,
                                          const std::string& mask) {
  switch (family) {
    case kFamilyIPv4: {
      in_addr_t mask_val = inet_network(mask.c_str());
      int subnet_prefix = 0;
      while (mask_val) {
        subnet_prefix++;
        mask_val <<= 1;
      }
      return subnet_prefix;
    }
    case kFamilyIPv6:
      NOTIMPLEMENTED();
      break;
    default:
      LOG(WARNING) << "Unexpected address family: " << family;
      break;
  }
  return 0;
}

// static
IPAddress IPAddress::GetAddressMaskFromPrefix(Family family, size_t prefix) {
  ByteString address_bytes(GetAddressLength(family));
  unsigned char* address_ptr = address_bytes.GetData();

  size_t bits = prefix;
  if (bits > GetMaxPrefixLength(family)) {
    bits = GetMaxPrefixLength(family);
  }

  while (bits > kBitsPerByte) {
    bits -= kBitsPerByte;
    *address_ptr++ = std::numeric_limits<uint8_t>::max();
  }

  // We are guaranteed to be before the end of the address data since even
  // if the prefix is the maximum, the loop above will end before we assign
  // and increment past the last byte.
  *address_ptr = ~((1 << (kBitsPerByte - bits)) - 1);

  return IPAddress(family, address_bytes);
}

// static
std::string IPAddress::GetAddressFamilyName(Family family) {
  switch (family) {
    case kFamilyIPv4:
      return kFamilyNameIPv4;
    case kFamilyIPv6:
      return kFamilyNameIPv6;
    default:
      return kFamilyNameUnknown;
  }
}

// static
std::optional<IPAddress> IPAddress::CreateFromByteStringAndPrefix(
    Family family, const ByteString& address, unsigned int prefix) {
  IPAddress ret(family, address, prefix);
  if (!ret.IsValid()) {
    return std::nullopt;
  }
  return ret;
}

// static
std::optional<IPAddress> IPAddress::CreateFromStringAndPrefix(
    const std::string& address_string, unsigned int prefix, Family family) {
  if (family != kFamilyIPv6) {
    IPAddress ipv4_address =
        IPAddress::CreateFromFamily(IPAddress::kFamilyIPv4);
    if (ipv4_address.SetAddressFromString(address_string)) {
      ipv4_address.set_prefix(prefix);
      return ipv4_address;
    }
  }
  if (family != kFamilyIPv4) {
    IPAddress ipv6_address =
        IPAddress::CreateFromFamily(IPAddress::kFamilyIPv6);
    if (ipv6_address.SetAddressFromString(address_string)) {
      ipv6_address.set_prefix(prefix);
      return ipv6_address;
    }
  }
  return std::nullopt;
}

// static
std::optional<IPAddress> IPAddress::CreateFromPrefixString(
    const std::string& address_string, Family family) {
  if (family != kFamilyIPv6) {
    IPAddress ipv4_address =
        IPAddress::CreateFromFamily(IPAddress::kFamilyIPv4);
    if (ipv4_address.SetAddressAndPrefixFromString(address_string)) {
      return ipv4_address;
    }
  }
  if (family != kFamilyIPv4) {
    IPAddress ipv6_address =
        IPAddress::CreateFromFamily(IPAddress::kFamilyIPv6);
    if (ipv6_address.SetAddressAndPrefixFromString(address_string)) {
      return ipv6_address;
    }
  }
  return std::nullopt;
}

std::optional<IPv4Address> IPAddress::ToIPv4Address() const {
  if (!IsValid() || family_ != kFamilyIPv4) {
    return std::nullopt;
  }

  return IPv4Address::CreateFromBytes(GetConstData(), GetLength());
}

std::optional<IPv6Address> IPAddress::ToIPv6Address() const {
  if (!IsValid() || family_ != kFamilyIPv6) {
    return std::nullopt;
  }

  return IPv6Address::CreateFromBytes(GetConstData(), GetLength());
}

std::optional<IPv4CIDR> IPAddress::ToIPv4CIDR() const {
  const auto ipv4_address = ToIPv4Address();
  if (!ipv4_address) {
    return std::nullopt;
  }

  return IPv4CIDR::CreateFromAddressAndPrefix(*ipv4_address, prefix_);
}

std::optional<IPv6CIDR> IPAddress::ToIPv6CIDR() const {
  const auto ipv6_address = ToIPv6Address();
  if (!ipv6_address) {
    return std::nullopt;
  }

  return IPv6CIDR::CreateFromAddressAndPrefix(*ipv6_address, prefix_);
}

bool IPAddress::SetAddressFromString(const std::string& address_string) {
  size_t address_length = GetAddressLength(family_);

  if (!address_length) {
    return false;
  }

  ByteString address(address_length);
  if (inet_pton(family_, address_string.c_str(), address.GetData()) <= 0) {
    return false;
  }
  address_ = address;
  return true;
}

bool IPAddress::SetAddressAndPrefixFromString(
    const std::string& address_string) {
  const auto address_parts = base::SplitString(
      address_string, "/", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  if (address_parts.size() != 2) {
    return false;
  }
  if (!SetAddressFromString(address_parts[0])) {
    return false;
  }
  size_t prefix;
  if (!base::StringToSizeT(address_parts[1], &prefix) ||
      prefix > GetMaxPrefixLength(family_)) {
    return false;
  }
  set_prefix(prefix);
  return true;
}

void IPAddress::SetAddressToDefault() {
  address_ = ByteString(GetAddressLength(family_));
}

bool IPAddress::IntoString(std::string* address_string) const {
  if (!IsValid()) {
    return false;
  }
  // Noting that INET6_ADDRSTRLEN > INET_ADDRSTRLEN
  char address_buf[INET6_ADDRSTRLEN];
  if (!inet_ntop(family_, GetConstData(), address_buf, sizeof(address_buf))) {
    return false;
  }
  *address_string = address_buf;
  return true;
}

std::string IPAddress::ToString() const {
  std::string out = "<unknown>";
  IntoString(&out);
  return out;
}

bool IPAddress::Equals(const IPAddress& b) const {
  return family_ == b.family_ && address_.Equals(b.address_) &&
         prefix_ == b.prefix_;
}

bool IPAddress::HasSameAddressAs(const IPAddress& b) const {
  return family_ == b.family_ && address_.Equals(b.address_);
}

IPAddress IPAddress::MaskWith(const IPAddress& b) const {
  CHECK(IsValid());
  CHECK(b.IsValid());
  CHECK_EQ(family(), b.family());

  ByteString address_bytes(address());
  address_bytes.BitwiseAnd(b.address());

  return IPAddress(family(), address_bytes);
}

IPAddress IPAddress::MergeWith(const IPAddress& b) const {
  CHECK(IsValid());
  CHECK(b.IsValid());
  CHECK_EQ(family(), b.family());

  ByteString address_bytes(address());
  address_bytes.BitwiseOr(b.address());

  return IPAddress(family(), address_bytes);
}

IPAddress IPAddress::GetNetworkPart() const {
  auto address = MaskWith(GetAddressMaskFromPrefix(family(), prefix()));
  address.set_prefix(prefix());
  return address;
}

IPAddress IPAddress::GetDefaultBroadcast() const {
  ByteString broadcast_bytes(
      GetAddressMaskFromPrefix(family(), prefix()).address());
  broadcast_bytes.BitwiseInvert();
  return MergeWith(IPAddress(family(), broadcast_bytes));
}

bool IPAddress::CanReachAddress(const IPAddress& b) const {
  if (family() != b.family()) {
    return false;
  }
  IPAddress b_prefixed(b);
  b_prefixed.set_prefix(prefix());
  return GetNetworkPart().HasSameAddressAs(b_prefixed.GetNetworkPart());
}

bool IPAddress::operator<(const IPAddress& b) const {
  CHECK(IsValid());
  CHECK(b.IsValid());
  if (family() == b.family()) {
    return address_ < b.address_;
  }
  // All IPv4 address are less than IPv6 addresses.
  return family() == kFamilyIPv4 && b.family() == kFamilyIPv6;
}

}  // namespace shill
