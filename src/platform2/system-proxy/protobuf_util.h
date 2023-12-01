// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SYSTEM_PROXY_PROTOBUF_UTIL_H_
#define SYSTEM_PROXY_PROTOBUF_UTIL_H_

#include <google/protobuf/message_lite.h>
#include <string>

namespace system_proxy {

// System-proxy daemon uses protobufs to communicate with the workers.
bool ReadProtobuf(int fd, google::protobuf::MessageLite* message);
bool WriteProtobuf(int fd, const google::protobuf::MessageLite& message);

}  // namespace system_proxy

#endif  // SYSTEM_PROXY_PROTOBUF_UTIL_H_
