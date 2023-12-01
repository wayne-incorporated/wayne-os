// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "system-proxy/protobuf_util.h"

#include <vector>

#include <base/files/file_util.h>

namespace system_proxy {

bool ReadProtobuf(int in_fd, google::protobuf::MessageLite* message) {
  size_t proto_size = 0;
  // The first part of the message will be the size of the actual message.
  // Because the message is a serialized protobuf, we need to read the whole
  // message before deserializing it.
  if (!base::ReadFromFD(in_fd, reinterpret_cast<char*>(&proto_size),
                        sizeof(proto_size)))
    return false;
  std::vector<char> buf(proto_size);
  // Tries to read exactly buf.size() bytes from in_fd and returns true if
  // succeeded, false otherwise. If the read() get interrupted by EINTR it will
  // resume reading by itself with a limited number of attempts.
  if (!base::ReadFromFD(in_fd, buf.data(), buf.size()))
    return false;

  return message->ParseFromArray(buf.data(), buf.size());
}

bool WriteProtobuf(int out_fd, const google::protobuf::MessageLite& message) {
  size_t size = message.ByteSizeLong();
  constexpr size_t kSpanSize = 1;
  if (!base::WriteFileDescriptor(
          out_fd, base::as_bytes(base::make_span(&size, kSpanSize)))) {
    return false;
  }

  return message.SerializeToFileDescriptor(out_fd);
}
}  // namespace system_proxy
