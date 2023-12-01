// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/mojo_proxy/message_stream.h"

#include <string>
#include <utility>

#include <base/files/file_util.h>
#include <base/logging.h>

#include "arc/vm/mojo_proxy/file_descriptor_util.h"

namespace arc {

namespace {

// Receives data and FDs from the given socket FD and returns true when the
// buffer is filled successfully.
bool ReceiveData(int fd,
                 char* buf,
                 size_t size,
                 std::vector<base::ScopedFD>* fds) {
  while (size > 0) {
    ssize_t result =
        fds ? Recvmsg(fd, buf, size, fds) : HANDLE_EINTR(read(fd, buf, size));
    if (result <= 0) {
      if (result == 0)
        LOG(ERROR) << "Unexpected EOF while receiving data.";
      else
        PLOG(ERROR) << "Failed to receive data.";
      return false;
    }
    fds = nullptr;  // No need to receive FDs again.
    buf += result;
    size -= result;
  }
  return true;
}

// Sends data and FDs to the given socket FD and return true upon success.
bool SendMsg(int fd,
             const char* buf,
             size_t size,
             const std::vector<base::ScopedFD>& fds) {
  ssize_t written = Sendmsg(fd, buf, size, fds);
  if (written < 0) {
    PLOG(ERROR) << "Failed to write proto";
    return false;
  }

  if (written < size) {
    auto sp = base::StringPiece(buf + written, size - written);
    if (!base::WriteFileDescriptor(fd, std::move(sp))) {
      PLOG(ERROR) << "Failed to write proto";
      return false;
    }
  }

  return true;
}

}  // namespace

MessageStream::MessageStream(base::ScopedFD fd) : fd_(std::move(fd)) {}

MessageStream::~MessageStream() = default;

bool MessageStream::Read(arc_proxy::MojoMessage* message,
                         std::vector<base::ScopedFD>* fds) {
  // Receive FDs and the message size.
  uint64_t size = 0;
  if (!ReceiveData(fd_.get(), reinterpret_cast<char*>(&size), sizeof(size),
                   fds)) {
    LOG(ERROR) << "Failed to receive message size.";
    return false;
  }

  // Read and parse the message.
  buf_.resize(size);
  if (!base::ReadFromFD(fd_.get(), buf_.data(), buf_.size())) {
    PLOG(ERROR) << "Failed to read a proto";
    return false;
  }

  if (!message->ParseFromArray(buf_.data(), buf_.size())) {
    LOG(ERROR) << "Failed to parse proto message";
    return false;
  }
  return true;
}

bool MessageStream::Write(const arc_proxy::MojoMessage& message,
                          const std::vector<base::ScopedFD>& fds) {
  const uint64_t size = message.ByteSizeLong();
  buf_.resize(sizeof(size) + size);

  struct Frame {
    uint64_t size;
    char data[];
  };
  Frame* frame = reinterpret_cast<Frame*>(buf_.data());
  frame->size = size;
  if (!message.SerializeToArray(frame->data, size)) {
    LOG(ERROR) << "Failed to serialize proto.";
    return false;
  }

  if (!SendMsg(fd_.get(), buf_.data(), buf_.size(), fds)) {
    PLOG(ERROR) << "Failed to write proto";
    return false;
  }
  return true;
}

}  // namespace arc
