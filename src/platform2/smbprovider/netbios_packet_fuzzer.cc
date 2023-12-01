// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <vector>

#include "smbprovider/netbios_packet_parser.h"

namespace {

void FuzzNetBiosParser(const uint8_t* data, size_t size) {
  if (size < 2) {
    return;
  }
  const uint16_t transaction_id = (data[0] << 8) | data[1];
  const std::vector<uint8_t> packet(data + 2, data + size);
  smbprovider::netbios::ParsePacket(packet, transaction_id);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzNetBiosParser(data, size);
  return 0;
}
