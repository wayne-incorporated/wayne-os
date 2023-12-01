// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/csme/mei_client_socket.h"

#include <error.h>
#include <fcntl.h>
#include <linux/mei.h>
#include <linux/uuid.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstring>
#include <string>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/logging.h>

namespace trunks {
namespace csme {

MeiClientSocket::MeiClientSocket(const std::string& mei_path,
                                 const uuid_le& guid)
    : mei_path_(mei_path) {
  DCHECK(!mei_path_.empty());
  memcpy(&guid_, &guid, sizeof(guid));
}

MeiClientSocket::~MeiClientSocket() {
  Uninitialize();
}

bool MeiClientSocket::IsSupport() {
  return base::PathExists(base::FilePath(mei_path_));
}

bool MeiClientSocket::Initialize() {
  if (initialized_) {
    return true;
  }
  DCHECK_EQ(fd_, -1);

  if (!InitializeInternal()) {
    Uninitialize();
    return false;
  }

  initialized_ = true;

  return true;
}

void MeiClientSocket::Uninitialize() {
  if (fd_ != -1) {
    close(fd_);
    fd_ = -1;
  }
}

bool MeiClientSocket::Send(const std::string& data,
                           bool /*wait_for_response_ready*/) {
  if (!initialized_ && !Initialize()) {
    LOG(ERROR) << __func__ << ": Not initialized.";
    return false;
  }
  const uint32_t message_size = data.size();
  ssize_t wsize = write(fd_, &message_size, sizeof(message_size));
  if (wsize != sizeof(message_size)) {
    LOG(ERROR) << __func__ << ": Bad written size of message header: " << wsize;
    return false;
  }
  wsize = write(fd_, data.data(), data.size());
  if (wsize != data.size()) {
    LOG(ERROR) << __func__ << ": Bad written size of payload: " << wsize;
    return false;
  }
  return true;
}

bool MeiClientSocket::Receive(std::string* data) {
  if (!initialized_ && !Initialize()) {
    LOG(ERROR) << __func__ << ": Not initialized.";
    return false;
  }
  uint32_t message_size = 0;
  ssize_t rsize = read(fd_, &message_size, sizeof(message_size));
  if (rsize != sizeof(message_size)) {
    LOG(ERROR) << "Unexpected message header size: " << rsize;
    return false;
  }
  data->resize(message_size);
  char* buffer = const_cast<char*>(data->data());
  for (ssize_t remaining_size = message_size; remaining_size > 0;) {
    const ssize_t rsize = read(fd_, buffer, remaining_size);
    if (rsize < 0) {
      PLOG(ERROR) << ": Error calling `read()`";
      data->clear();
      return false;
    }
    buffer += rsize;
    remaining_size -= rsize;
  }
  return true;
}

bool MeiClientSocket::InitializeInternal() {
  DCHECK_EQ(fd_, -1);

  fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd_ == -1) {
    PLOG(ERROR) << __func__ << ": Error calling `socket()`";
    return false;
  }
  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  CHECK_LT(mei_path_.size(), sizeof(addr.sun_path));
  strncpy(addr.sun_path, mei_path_.c_str(), sizeof(addr.sun_path));
  if (connect(fd_, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
    PLOG(ERROR) << __func__ << ": Error when connecting socket";
    return false;
  }
  return true;
}

}  // namespace csme
}  // namespace trunks
