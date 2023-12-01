// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_SOMMELIER_TESTING_MOCK_WAYLAND_CHANNEL_H_
#define VM_TOOLS_SOMMELIER_TESTING_MOCK_WAYLAND_CHANNEL_H_

#include <gmock/gmock.h>
#include <string>

#include "../sommelier-ctx.h"  // NOLINT(build/include_directory)
#include "../virtualization/wayland_channel.h"  // NOLINT(build/include_directory)

// Help gtest print Wayland message streams on expectation failure.
//
// This is defined in the test file mostly to avoid the main program depending
// on <iostream> and <string> merely for testing purposes. Also, it doesn't
// print the entire struct, just the data buffer, so it's not a complete
// representation of the object.
std::ostream& operator<<(std::ostream& os, const WaylandSendReceive& w);

namespace vm_tools {
namespace sommelier {

using ::testing::PrintToString;

// Mock of Sommelier's Wayland connection to the host compositor.
class MockWaylandChannel : public WaylandChannel {
 public:
  MockWaylandChannel() = default;

  MOCK_METHOD(int32_t, init, (), (override));
  MOCK_METHOD(bool, supports_dmabuf, (), (override));
  MOCK_METHOD(int32_t,
              create_context,
              (int& out_socket_fd),
              (override));  // NOLINT(runtime/references)
  MOCK_METHOD(int32_t,
              create_pipe,
              (int& out_pipe_fd),
              (override));  // NOLINT(runtime/references)
  MOCK_METHOD(int32_t,
              send,
              (const struct WaylandSendReceive& send),
              (override));
  MOCK_METHOD(
      int32_t,
      handle_channel_event,
      (enum WaylandChannelEvent & event_type,  // NOLINT(runtime/references)
       struct WaylandSendReceive& receive,     // NOLINT(runtime/references)
       int& out_read_pipe),                    // NOLINT(runtime/references)
      (override));

  MOCK_METHOD(int32_t,
              allocate,
              (const struct WaylandBufferCreateInfo& create_info,
               struct WaylandBufferCreateOutput&
                   create_output),  // NOLINT(runtime/references)
              (override));
  MOCK_METHOD(int32_t, sync, (int dmabuf_fd, uint64_t flags), (override));
  MOCK_METHOD(int32_t,
              handle_pipe,
              (int read_fd,
               bool readable,
               bool& hang_up),  // NOLINT(runtime/references)
              (override));
  MOCK_METHOD(size_t, max_send_size, (), (override));

 protected:
  ~MockWaylandChannel() override = default;
};

// Match a WaylandSendReceive buffer containing exactly one Wayland message
// with given object ID and opcode.
MATCHER_P2(ExactlyOneMessage,
           object_id,
           opcode,
           std::string(negation ? "not " : "") +
               "exactly one Wayland message for object ID " +
               PrintToString(object_id) + ", opcode " + PrintToString(opcode)) {
  const struct WaylandSendReceive& send = arg;
  if (send.data_size < sizeof(uint32_t) * 2) {
    // Malformed packet (too short)
    return false;
  }

  uint32_t actual_object_id = *reinterpret_cast<uint32_t*>(send.data);
  uint32_t second_word = *reinterpret_cast<uint32_t*>(send.data + 4);
  uint16_t message_size_in_bytes = second_word >> 16;
  uint16_t actual_opcode = second_word & 0xffff;

  // ID and opcode must match expectation, and we must see exactly one message
  // with the indicated length.
  return object_id == actual_object_id && opcode == actual_opcode &&
         message_size_in_bytes == send.data_size;
};

// Match a WaylandSendReceive buffer containing at least one Wayland message
// with given object ID and opcode.
MATCHER_P2(AtLeastOneMessage,
           object_id,
           opcode,
           std::string(negation ? "no Wayland messages "
                                : "at least one Wayland message ") +
               "for object ID " + PrintToString(object_id) + ", opcode " +
               PrintToString(opcode)) {
  const struct WaylandSendReceive& send = arg;
  if (send.data_size < sizeof(uint32_t) * 2) {
    // Malformed packet (too short)
    return false;
  }
  for (uint32_t i = 0; i < send.data_size;) {
    uint32_t actual_object_id = *reinterpret_cast<uint32_t*>(send.data + i);
    uint32_t second_word = *reinterpret_cast<uint32_t*>(send.data + i + 4);
    uint16_t message_size_in_bytes = second_word >> 16;
    uint16_t actual_opcode = second_word & 0xffff;
    if (i + message_size_in_bytes > send.data_size) {
      // Malformed packet (stated message size overflows buffer)
      break;
    }
    if (object_id == actual_object_id && opcode == actual_opcode) {
      return true;
    }
    i += message_size_in_bytes;
  }
  return false;
}

// Match a WaylandSendReceive buffer containing a string.
// TODO(cpelling): This is currently very naive; it doesn't respect
// boundaries between messages or their arguments. Fix me.
MATCHER_P(AnyMessageContainsString,
          str,
          std::string("a Wayland message containing string ") + str) {
  const struct WaylandSendReceive& send = arg;
  size_t prefix_len = sizeof(uint32_t) * 2;
  std::string data_as_str(reinterpret_cast<char*>(send.data + prefix_len),
                          send.data_size - prefix_len);

  return data_as_str.find(str) != std::string::npos;
}

}  // namespace sommelier
}  // namespace vm_tools

#endif  // VM_TOOLS_SOMMELIER_TESTING_MOCK_WAYLAND_CHANNEL_H_
