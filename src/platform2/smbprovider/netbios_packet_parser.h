// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBPROVIDER_NETBIOS_PACKET_PARSER_H_
#define SMBPROVIDER_NETBIOS_PACKET_PARSER_H_

#include <string>
#include <vector>

namespace smbprovider {
namespace netbios {

constexpr int kFileServerNodeType = 0x20;
// Each Server Entry is 18 bytes. 15 byte name, 1 byte type, 2 byte flags.
constexpr int kServerNameLength = 15;
constexpr int kServerEntrySize = kServerNameLength + 3;

// Parses a NetBios Name Query Response packet into a vector of strings.
// If the packet is not a response to the broadcast with |transaction_id| or is
// a malformed NetBios Name Response packet, an empty vector is returned.
std::vector<std::string> ParsePacket(const std::vector<uint8_t>& packet,
                                     uint16_t transaction_id);

}  // namespace netbios
}  // namespace smbprovider

#endif  // SMBPROVIDER_NETBIOS_PACKET_PARSER_H_
