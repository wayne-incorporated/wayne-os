// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/delegate/utils/psr_cmd.h"

#include <ctime>
#include <fcntl.h>
#include <fstream>
#include <errno.h>
#include <linux/mei.h>
#include <memory>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/memory/ref_counted.h>

namespace diagnostics {
namespace psr {

PsrCmd::PsrCmd(const int fd) {
  mei_fd_ = fd;
  mei_connect_data_ = new mei_connect_client_data;
  mei_connect_data_->in_client_uuid = kGuid;
}

PsrCmd::~PsrCmd() {
  delete mei_connect_data_;
}
bool PsrCmd::MeiConnect() {
  if (ioctl(mei_fd_, IOCTL_MEI_CONNECT_CLIENT, mei_connect_data_) == -1) {
    int err = errno;
    LOG(ERROR) << "ioctl MEI connect failed: " << strerror(err);
    return false;
  }

  return true;
}

bool PsrCmd::MeiSend(void* buffer, ssize_t buff_len) {
  ssize_t written_bytes = write(mei_fd_, buffer, buff_len);
  if (written_bytes != buff_len) {
    int err = errno;
    LOG(ERROR) << "Failed writing to /dev/mei0: " << strerror(err);
    return false;
  }

  return true;
}

bool PsrCmd::MeiReceive(std::vector<uint8_t>& buffer, ssize_t& buff_len) {
  // Set timeout.
  struct timeval tv;
  tv.tv_sec = kMaxTimeoutSec;
  tv.tv_usec = (kMaxTimeoutSec % 1000) * 1000;

  // Check if kCrosMeiPath data ready to read.
  fd_set readfds;
  FD_ZERO(&readfds);
  FD_SET(mei_fd_, &readfds);

  int err;
  int ready = select(mei_fd_ + 1, &readfds, nullptr, nullptr, &tv);
  if (ready < 0) {
    err = errno;
    LOG(ERROR) << __func__ << "Select error: " << strerror(errno);
    return false;
  } else if (!ready) {
    err = errno;
    LOG(ERROR) << __func__ << "Timeout: " << strerror(errno);
    return false;
  } else if (!FD_ISSET(mei_fd_, &readfds)) {
    err = errno;
    LOG(ERROR) << __func__ << ": Internal error: " << strerror(errno);
    return false;
  }

  ssize_t read_bytes =
      read(mei_fd_, static_cast<void*>(buffer.data()), buff_len);
  if (read_bytes < 0) {
    err = errno;
    LOG(ERROR) << __func__ << ": Reading error: " << strerror(errno);
    return false;
  } else if (!read_bytes) {
    err = errno;
    LOG(ERROR) << __func__ << ": No response: " << strerror(errno);
    return false;
  }

  buff_len = read_bytes;

  return true;
}

PsrCmd::CmdStatus PsrCmd::Transaction(HeciGetRequest& tx_buff,
                                      PsrHeciResp& rx_buff) {
  if (!MeiConnect()) {
    int err = errno;
    LOG(ERROR) << __func__ << ": Unable to connect: " << strerror(err);
    return kMeiOpenErr;
  }

  ssize_t buff_size = static_cast<ssize_t>(
      mei_connect_data_->out_client_properties.max_msg_length);

  if (buff_size < (sizeof(rx_buff.header) + sizeof(rx_buff.status))) {
    int err = errno;
    LOG(ERROR) << "Invalid argument while invokes MEI request: "
               << strerror(err);
    return kInsufficentBuffer;
  }

  ssize_t tx_len = sizeof(tx_buff);
  if (tx_len > buff_size)
    return kInsufficentBuffer;

  if (!MeiSend(reinterpret_cast<void*>(&tx_buff), tx_len))
    return kMeiSendErr;

  std::vector<uint8_t> rcv_buff;
  rcv_buff.reserve(buff_size);
  if (!MeiReceive(rcv_buff, buff_size))
    return kMeiRecErr;

  ssize_t rx_len = sizeof(rx_buff);
  if (buff_size > rx_len)
    return kInsufficentBuffer;

  std::memcpy(reinterpret_cast<void*>(&rx_buff),
              static_cast<void*>(rcv_buff.data()), buff_size);

  return kSuccess;
}

bool PsrCmd::GetPlatformServiceRecord(PsrHeciResp& psr_blob) {
  HeciGetRequest request;

  request.header.command = kGetRecordCmdIdx;
  request.header.length = kPaddingSize;

  CmdStatus status = Transaction(request, psr_blob);

  if (kInsufficentBuffer == status) {
    int err = errno;
    LOG(ERROR) << "Buffer is too small while invokes MEI request: "
               << strerror(err);
    return false;
  } else if (status > 0) {
    LOG(ERROR) << "Get PSR status error: " << status;
    return false;
  }

  return true;
}

std::string PsrCmd::IdToHexString(uint8_t uid[], int id_len) {
  std::stringstream id;

  id << std::hex;
  for (int i = 0; i < id_len; ++i) {
    id << std::setw(2) << std::setfill('0') << static_cast<int>(uid[i]);
  }
  return id.str();
}

}  // namespace psr
}  // namespace diagnostics
