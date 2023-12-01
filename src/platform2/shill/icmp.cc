// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/icmp.h"

#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>

#include <base/check_op.h>
#include <base/logging.h>
#include <base/notreached.h>

#include "shill/logging.h"
#include "shill/net/sockets.h"

namespace shill {

const int Icmp::kIcmpEchoCode = 0;  // value specified in RFC 792.

Icmp::Icmp()
    : sockets_(new Sockets()),
      socket_(-1),
      destination_(IPAddress::CreateFromFamily(IPAddress::kFamilyUnknown)),
      interface_index_(-1) {}

Icmp::~Icmp() = default;

bool Icmp::Start(const IPAddress& destination, int interface_index) {
  if (!destination.IsValid()) {
    LOG(ERROR) << "Destination address is not valid.";
    return false;
  }

  int socket = -1;
  if (destination.family() == IPAddress::kFamilyIPv4) {
    socket = sockets_->Socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
  } else if (destination.family() == IPAddress::kFamilyIPv6) {
    socket =
        sockets_->Socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6);
  } else {
    NOTREACHED();
  }

  if (socket == -1) {
    PLOG(ERROR) << "Could not create ICMP socket";
    Stop();
    return false;
  }
  socket_ = socket;
  socket_closer_.reset(new ScopedSocketCloser(sockets_.get(), socket_));

  if (sockets_->SetNonBlocking(socket_) != 0) {
    PLOG(ERROR) << "Could not set socket to be non-blocking";
    Stop();
    return false;
  }

  destination_ = destination;
  interface_index_ = interface_index;
  return true;
}

void Icmp::Stop() {
  socket_closer_.reset();
  socket_ = -1;
}

bool Icmp::IsStarted() const {
  return socket_closer_.get();
}

bool Icmp::TransmitV4EchoRequest(uint16_t id, uint16_t seq_num) {
  struct icmphdr icmp_header;
  memset(&icmp_header, 0, sizeof(icmp_header));
  icmp_header.type = ICMP_ECHO;
  icmp_header.code = kIcmpEchoCode;
  icmp_header.un.echo.id = id;
  icmp_header.un.echo.sequence = seq_num;
  icmp_header.checksum = ComputeIcmpChecksum(icmp_header, sizeof(icmp_header));

  struct sockaddr_in destination_address;
  destination_address.sin_family = AF_INET;
  CHECK_EQ(sizeof(destination_address.sin_addr.s_addr),
           destination_.GetLength());
  memcpy(&destination_address.sin_addr.s_addr,
         destination_.address().GetConstData(),
         sizeof(destination_address.sin_addr.s_addr));

  int result =
      sockets_->SendTo(socket_, &icmp_header, sizeof(icmp_header), 0,
                       reinterpret_cast<struct sockaddr*>(&destination_address),
                       sizeof(destination_address));
  int expected_result = sizeof(icmp_header);
  if (result != expected_result) {
    if (result < 0) {
      PLOG(ERROR) << "Socket sendto failed";
    } else if (result < expected_result) {
      LOG(ERROR) << "Socket sendto returned " << result
                 << " which is less than the expected result "
                 << expected_result;
    }
    return false;
  }

  return true;
}

bool Icmp::TransmitV6EchoRequest(uint16_t id, uint16_t seq_num) {
  struct icmp6_hdr icmp_header;
  memset(&icmp_header, 0, sizeof(icmp_header));
  icmp_header.icmp6_type = ICMP6_ECHO_REQUEST;
  icmp_header.icmp6_code = kIcmpEchoCode;
  icmp_header.icmp6_id = id;
  icmp_header.icmp6_seq = seq_num;
  // icmp6_cksum is filled in by the kernel for IPPROTO_ICMPV6 sockets
  // (RFC3542 section 3.1)

  struct sockaddr_in6 destination_address;
  memset(&destination_address, 0, sizeof(destination_address));
  destination_address.sin6_family = AF_INET6;
  destination_address.sin6_scope_id = interface_index_;
  CHECK_EQ(sizeof(destination_address.sin6_addr.s6_addr),
           destination_.GetLength());
  memcpy(&destination_address.sin6_addr.s6_addr,
         destination_.address().GetConstData(),
         sizeof(destination_address.sin6_addr.s6_addr));

  int result =
      sockets_->SendTo(socket_, &icmp_header, sizeof(icmp_header), 0,
                       reinterpret_cast<struct sockaddr*>(&destination_address),
                       sizeof(destination_address));
  int expected_result = sizeof(icmp_header);
  if (result != expected_result) {
    if (result < 0) {
      PLOG(ERROR) << "Socket sendto failed";
    } else if (result < expected_result) {
      LOG(ERROR) << "Socket sendto returned " << result
                 << " which is less than the expected result "
                 << expected_result;
    }
    return false;
  }

  return true;
}

bool Icmp::TransmitEchoRequest(uint16_t id, uint16_t seq_num) {
  if (!IsStarted()) {
    return false;
  }

  if (destination_.family() == IPAddress::kFamilyIPv4) {
    return TransmitV4EchoRequest(id, seq_num);
  } else {
    return TransmitV6EchoRequest(id, seq_num);
  }
}

// static
uint16_t Icmp::ComputeIcmpChecksum(const struct icmphdr& hdr, size_t len) {
  // Compute Internet Checksum for "len" bytes beginning at location "hdr".
  // Adapted directly from the canonical implementation in RFC 1071 Section 4.1.
  uint32_t sum = 0;
  const uint16_t* addr = reinterpret_cast<const uint16_t*>(&hdr);

  while (len > 1) {
    sum += *addr;
    ++addr;
    len -= sizeof(*addr);
  }

  // Add left-over byte, if any.
  if (len > 0) {
    sum += *reinterpret_cast<const uint8_t*>(addr);
  }

  // Fold 32-bit sum to 16 bits.
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  return static_cast<uint16_t>(~sum);
}

}  // namespace shill
