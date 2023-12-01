// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "mock-wayland-channel.h"  // NOLINT(build/include_directory)

#include <string>

std::ostream& operator<<(std::ostream& os, const WaylandSendReceive& w) {
  // Partially decode the data buffer. The content of messages is not decoded,
  // except their object ID and opcode.
  size_t i = 0;
  while (i < w.data_size) {
    uint32_t object_id = *reinterpret_cast<uint32_t*>(w.data + i);
    uint32_t second_word = *reinterpret_cast<uint32_t*>(w.data + i + 4);
    uint16_t message_size_in_bytes = second_word >> 16;
    uint16_t opcode = second_word & 0xffff;
    os << "[object ID " << object_id << ", opcode " << opcode << ", length "
       << message_size_in_bytes;

    uint16_t size = MIN(message_size_in_bytes, w.data_size - i);
    if (size > sizeof(uint32_t) * 2) {
      os << ", args=[";
      for (int j = sizeof(uint32_t) * 2; j < size; ++j) {
        char byte = w.data[i + j];
        if (isprint(byte)) {
          os << byte;
        } else {
          os << "\\" << static_cast<int>(byte);
        }
      }
      os << "]";
    }
    os << "]";
    i += message_size_in_bytes;
  }
  if (i != w.data_size) {
    os << "[WARNING: " << (w.data_size - i) << "undecoded trailing bytes]";
  }

  return os;
}
