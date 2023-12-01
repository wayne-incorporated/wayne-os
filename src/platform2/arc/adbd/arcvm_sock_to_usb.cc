/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "arc/adbd/arcvm_sock_to_usb.h"

#include <fcntl.h>
#include <unistd.h>

#include <vector>

#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>

#define EXIT_IF(f, msg)                        \
  do {                                         \
    if ((f)) {                                 \
      PLOG(ERROR) << (msg);                    \
      /* Don't use CHECK() or fatal logging */ \
      _exit(EXIT_FAILURE);                     \
    }                                          \
  } while (false)

namespace adbd {

ArcVmSockToUsb::ArcVmSockToUsb(const int sock_fd, const int usb_fd)
    : sock_fd_(sock_fd), usb_fd_(usb_fd), thread_("sock->usb") {
  DCHECK_GE(sock_fd_, 0);
  DCHECK_GE(usb_fd_, 0);
}

ArcVmSockToUsb::~ArcVmSockToUsb() = default;

bool ArcVmSockToUsb::Start() {
  if (!thread_.StartWithOptions(
          base::Thread::Options(base::MessagePumpType::IO, 0))) {
    LOG(ERROR) << "Failed to start thread";
    return false;
  }
  if (!thread_.task_runner()->PostTask(
          FROM_HERE,
          base::BindOnce(&ArcVmSockToUsb::Run, base::Unretained(this)))) {
    LOG(ERROR) << "Failed to dispatch task to thread";
    return false;
  }
  LOG(INFO) << "ArcVmSockToUsb started";
  return true;
}

void ArcVmSockToUsb::Run() {
  std::vector<char> buf(kUsbWriteBufSize);
  while (true) {
    char* data = buf.data();
    EXIT_IF(!base::ReadFromFD(sock_fd_, data, kAmessageSize),
            "failed to read adb message from socket");

    EXIT_IF(!base::WriteFileDescriptor(usb_fd_,
                                       base::StringPiece(data, kAmessageSize)),
            "failed to write adb message to usb");

    // The ADB design of USB transport splits the header and the optional
    // data payload of a message into two USB transfers. The peer expects
    // the exact package length of each transfer to USB layers. But such
    // behavior seems not for socket transport. As a result, we have to
    // step into the traffic from the socket to split the data properly
    // before relaying the data to USB endpoint.
    // We achieve this by using the depth control of buffer. Data won't be
    // sent until we have the expected amount.
    int payload_len = 0;
    for (int i = 0; i < 4; i++) {
      payload_len +=
          static_cast<unsigned char>(data[kAmessageDataLenOffset + i]) << 8 * i;
    }
    if (payload_len > kAdbPayloadMaxSize) {
      LOG(ERROR) << "payload length is too big";
      _exit(EXIT_FAILURE);
    }
    if (payload_len > 0) {
      EXIT_IF(!base::ReadFromFD(sock_fd_, data, payload_len),
              "failed to read adb payload from socket");
      EXIT_IF(!base::WriteFileDescriptor(usb_fd_,
                                         base::StringPiece(data, payload_len)),
              "failed to write adb payload to usb");
    }
  }
}

}  // namespace adbd
