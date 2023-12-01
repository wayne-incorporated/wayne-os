// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/vsh/utils.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/posix/eintr_wrapper.h>
#include <brillo/message_loops/message_loop.h>

using google::protobuf::MessageLite;

namespace vm_tools {
namespace vsh {
namespace {

bool SendAllBytes(int sockfd, const uint8_t* buf, uint32_t buf_size) {
  if (!base::WriteFileDescriptor(
          sockfd, base::as_bytes(base::make_span(buf, buf_size)))) {
    PLOG(ERROR) << "Failed to write message to socket";
    return false;
  }

  return true;
}

void ShutdownTask() {
  brillo::MessageLoop::current()->BreakLoop();
}

}  // namespace

struct MessagePacket {
  uint32_t size;
  uint8_t payload[kMaxMessageSize];
};
static_assert(sizeof(MessagePacket) == sizeof(uint32_t) + kMaxMessageSize,
              "MessagePacket must not have implicit paddings");

bool SendMessage(int sockfd, const MessageLite& message) {
  size_t msg_size = message.ByteSizeLong();
  if (msg_size > kMaxMessageSize) {
    LOG(ERROR) << "Serialized message too large: " << msg_size;
    return false;
  }

  // Pack size and data into a buffer to send them through 1 vsock packet
  MessagePacket msg;
  msg.size = htole32(msg_size);
  if (!message.SerializeToArray(msg.payload, kMaxMessageSize)) {
    LOG(ERROR) << "Failed to serialize message";
    return false;
  }

  if (!SendAllBytes(sockfd, reinterpret_cast<uint8_t*>(&msg),
                    sizeof(uint32_t) + msg_size)) {
    return false;
  }

  return true;
}

bool RecvMessage(int sockfd, MessageLite* message) {
  MessagePacket msg;

  if (!base::ReadFromFD(sockfd, reinterpret_cast<char*>(&msg.size),
                        sizeof(msg.size))) {
    LOG(ERROR) << "Failed to read message from socket";
    return false;
  }
  msg.size = le32toh(msg.size);

  if (msg.size > kMaxMessageSize) {
    LOG(ERROR) << "Message size of " << msg.size << " exceeds max message size "
               << kMaxMessageSize;
    return false;
  }

  if (!base::ReadFromFD(sockfd, reinterpret_cast<char*>(msg.payload),
                        msg.size)) {
    LOG(ERROR) << "Failed to read message from socket";
    return false;
  }

  if (!message->ParseFromArray(msg.payload, msg.size)) {
    LOG(ERROR) << "Failed to parse message";
    return false;
  }

  return true;
}

// Posts a shutdown task to the main message loop.
void Shutdown() {
  brillo::MessageLoop::current()->PostTask(FROM_HERE,
                                           base::BindOnce(&ShutdownTask));
}

bool WriteKernelLogToFd(int fd,
                        logging::LogSeverity severity,
                        std::string_view prefix,
                        const std::string& message,
                        size_t message_start) {
  std::string_view priority;
  switch (severity) {
    case logging::LOGGING_VERBOSE:
      priority = "<7>";
      break;
    case logging::LOGGING_INFO:
      priority = "<6>";
      break;
    case logging::LOGGING_WARNING:
      priority = "<4>";
      break;
    case logging::LOGGING_ERROR:
      priority = "<3>";
      break;
    case logging::LOGGING_FATAL:
      priority = "<2>";
      break;
    default:
      priority = "<5>";
      break;
  }

  const struct iovec iovs[] = {
      {
          .iov_base = static_cast<void*>(const_cast<char*>(priority.data())),
          .iov_len = priority.length(),
      },
      {
          .iov_base = static_cast<void*>(const_cast<char*>(prefix.data())),
          .iov_len = prefix.length(),
      },
      {
          .iov_base = static_cast<void*>(
              const_cast<char*>(message.c_str() + message_start)),
          .iov_len = message.length() - message_start,
      },
  };

  ssize_t count = 0;
  for (const struct iovec& iov : iovs) {
    count += iov.iov_len;
  }

  ssize_t ret =
      HANDLE_EINTR(writev(fd, iovs, sizeof(iovs) / sizeof(struct iovec)));

  return ret == count;
}

}  // namespace vsh
}  // namespace vm_tools
