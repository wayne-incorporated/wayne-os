/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "arc/adbd/arcvm_usb_to_sock.h"

#include <fcntl.h>
#include <unistd.h>

#include <vector>

#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>

namespace adbd {
namespace {

// Size of the buffer read from USB (OUT) endpoint.
constexpr size_t kUsbReadBufSize = 4 * 1024;
}  // namespace

ArcVmUsbToSock::ArcVmUsbToSock(const int sock_fd, const int usb_fd)
    : sock_fd_(sock_fd), usb_fd_(usb_fd), thread_("usb->sock") {
  DCHECK_GE(sock_fd_, 0);
  DCHECK_GE(usb_fd_, 0);
}

ArcVmUsbToSock::~ArcVmUsbToSock() = default;

bool ArcVmUsbToSock::Start() {
  if (!thread_.StartWithOptions(
          base::Thread::Options(base::MessagePumpType::IO, 0))) {
    LOG(ERROR) << "Failed to start thread";
    return false;
  }
  if (!thread_.task_runner()->PostTask(
          FROM_HERE,
          base::BindOnce(&ArcVmUsbToSock::Run, base::Unretained(this)))) {
    LOG(ERROR) << "Failed to dispatch task to thread";
    return false;
  }
  LOG(INFO) << "ArcVmUsbToSock started";
  return true;
}

void ArcVmUsbToSock::Run() {
  std::vector<char> buf(kUsbReadBufSize);

  // Most of the time we will be blocked in reading from USB
  // Process any data pending in the buffer first before pull
  // more from USB endpoint.
  while (true) {
    char* data = buf.data();
    auto ret = HANDLE_EINTR(read(usb_fd_, data, kUsbReadBufSize));
    if (ret < 0) {
      PLOG(ERROR) << "failed to read from usb endpoint";

      // When any channel broke, there is no point to keep the whole bridge
      // service, so we just quit the whole service and rely on the outside
      // to restart the service.
      break;
    }
    if (ret &&
        !base::WriteFileDescriptor(sock_fd_, base::StringPiece(data, ret))) {
      PLOG(ERROR) << "failed to write to socket";
      break;
    }
  }
  _exit(EXIT_FAILURE);
}

}  // namespace adbd
