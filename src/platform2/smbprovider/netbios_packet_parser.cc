// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbprovider/netbios_packet_parser.h"

#include <utility>

#include <base/check_op.h>
#include <base/logging.h>
#include <base/strings/string_util.h>

namespace smbprovider {
namespace netbios {
namespace {

// https://tools.ietf.org/html/rfc1002
// Section 4.2.13
constexpr int kMinimumValidPacketSize = 26;
constexpr int kNBNSResourceRecord = 0x20;
constexpr int kNBNSSTATUSResourceRecord = 0x21;
// Packet Offsets
constexpr int kEntriesOffset = 25;
constexpr int kEntryCountOffset = 24;
constexpr int kNameLengthOffset = 12;
constexpr int kPositiveResponseOffset = 14;

// Checks whether a NetBios Name Response packet corresponds to the
// transaction.
bool HasValidTransactionId(const std::vector<uint8_t>& packet,
                           uint16_t expected_transaction_id) {
  DCHECK_GE(packet.size(), 2);

  const uint16_t actual_transaction_id = (packet[0] << 8) | packet[1];

  return actual_transaction_id == expected_transaction_id;
}

// Checks whether a NetBios Name Response packet is a positive response.
bool IsPositiveNameResponse(const std::vector<uint8_t>& packet,
                            uint32_t byte_index) {
  DCHECK_GT(packet.size(), byte_index + 1);

  const uint16_t node_status =
      (packet[byte_index] << 8) | packet[byte_index + 1];

  return node_status == kNBNSResourceRecord ||
         node_status == kNBNSSTATUSResourceRecord;
}

size_t GetExpectedPacketLength(uint8_t name_length, uint8_t entry_count) {
  return kEntriesOffset + name_length + entry_count * kServerEntrySize;
}

}  // namespace

std::vector<std::string> ParsePacket(const std::vector<uint8_t>& packet,
                                     uint16_t transaction_id) {
  if (packet.size() < kMinimumValidPacketSize) {
    return std::vector<std::string>();
  }

  // Check the transaction id.
  if (!HasValidTransactionId(packet, transaction_id)) {
    // This response is not to our broadcast.
    return std::vector<std::string>();
  }

  // Get name length.
  const uint8_t name_length = packet[kNameLengthOffset];

  // Check if it's a Positive response.
  if (kPositiveResponseOffset + name_length + 1 >= packet.size()) {
    return std::vector<std::string>();
  }
  if (!IsPositiveNameResponse(packet, kPositiveResponseOffset + name_length)) {
    // Negative response to the broadcast.
    return std::vector<std::string>();
  }

  // Get Address List entry count.
  if (kEntryCountOffset + name_length >= packet.size()) {
    return std::vector<std::string>();
  }
  const uint8_t entry_count = packet[kEntryCountOffset + name_length];

  // Check that there are the correct number of bytes remaining in the packet.
  if (GetExpectedPacketLength(name_length, entry_count) > packet.size()) {
    return std::vector<std::string>();
  }

  // Get Servers.
  uint32_t byte_index = kEntriesOffset + name_length;
  std::vector<std::string> servers;
  for (int i = 0; i < entry_count; ++i) {
    DCHECK_LE(byte_index + kServerEntrySize, packet.size());

    // Get Server name.
    std::string server(packet.begin() + byte_index,
                       packet.begin() + byte_index + kServerNameLength);
    byte_index += kServerNameLength;

    // Get type.
    const uint8_t type = packet[byte_index];
    byte_index += 1;
    if (type == kFileServerNodeType) {
      base::TrimWhitespaceASCII(server, base::TRIM_TRAILING, &server);
      servers.push_back(std::move(server));
    }

    // Skip flags.
    byte_index += 2;
  }

  return servers;
}

}  // namespace netbios
}  // namespace smbprovider
