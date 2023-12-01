// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/csme/mei_client_char_device.h"

#include <error.h>
#include <fcntl.h>
#include <linux/mei.h>
#include <linux/uuid.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <unistd.h>

#include <cstring>
#include <memory>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/time/time.h>

namespace trunks {
namespace csme {

namespace {

constexpr base::TimeDelta kSelectTimeout = base::Seconds(20);
};

MeiClientCharDevice::MeiClientCharDevice(const std::string& mei_path,
                                         const uuid_le& guid)
    : mei_path_(mei_path) {
  DCHECK(!mei_path_.empty());
  memcpy(&guid_, &guid, sizeof(guid));
}

MeiClientCharDevice::MeiClientCharDevice(const std::string& mei_path,
                                         const uuid_le& guid,
                                         hwsec_foundation::Syscaller* syscaller)
    : MeiClientCharDevice(mei_path, guid) {
  syscaller_ = syscaller;
}

MeiClientCharDevice::~MeiClientCharDevice() {
  Uninitialize();
}

bool MeiClientCharDevice::IsSupport() {
  return base::PathExists(base::FilePath(mei_path_));
}

bool MeiClientCharDevice::Initialize() {
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

void MeiClientCharDevice::Uninitialize() {
  if (fd_ != -1) {
    syscaller_->Close(fd_);
    fd_ = -1;
  }
}

bool MeiClientCharDevice::Send(const std::string& data,
                               bool wait_for_response_ready) {
  if (!initialized_ && !Initialize()) {
    LOG(ERROR) << __func__ << ": Not initialized.";
    return false;
  }
  if (data.size() > max_message_size_) {
    LOG(WARNING) << __func__ << ": Data size too large: " << data.size()
                 << ", shoud be less than " << max_message_size_;
  }
  ssize_t wsize = syscaller_->Write(fd_, data.data(), data.size());
  if (wsize != data.size()) {
    LOG(ERROR) << __func__ << ": Bad written size of payload: " << wsize;
    return false;
  }
  if (wait_for_response_ready && !EnsureWriteSuccess()) {
    return false;
  }

  return true;
}

bool MeiClientCharDevice::Receive(std::string* data) {
  if (!initialized_ && !Initialize()) {
    LOG(ERROR) << __func__ << ": Not initialized.";
    return false;
  }

  ssize_t rsize =
      syscaller_->Read(fd_, message_buffer_.data(), max_message_size_);
  if (rsize < 0) {
    PLOG(ERROR) << ": Error calling `read()`";
    return false;
  }
  data->assign(message_buffer_.begin(), message_buffer_.begin() + rsize);
  return true;
}

bool MeiClientCharDevice::InitializeInternal() {
  DCHECK_EQ(fd_, -1);

  fd_ = syscaller_->Open(mei_path_.c_str(), O_RDWR);
  if (fd_ == -1) {
    PLOG(ERROR) << __func__ << ": Error calling `open()`";
    return false;
  }
  struct mei_connect_client_data data = {};
  memcpy(&data.in_client_uuid, &guid_, sizeof(guid_));

  int result = syscaller_->Ioctl(fd_, IOCTL_MEI_CONNECT_CLIENT, &data);
  if (result) {
    PLOG(ERROR) << __func__ << ": Error calling `ioctl()`: " << result;
    Uninitialize();
    return false;
  }
  if (data.out_client_properties.max_msg_length <= 0) {
    LOG(DFATAL) << __func__ << ": Limit to message size too small.";
    return false;
  }

  max_message_size_ = data.out_client_properties.max_msg_length;
  message_buffer_.resize(max_message_size_);

  return true;
}

bool MeiClientCharDevice::EnsureWriteSuccess() {
  struct timeval tv = {
      .tv_sec = kSelectTimeout.InSeconds(),
  };
  fd_set set;
  FD_ZERO(&set);
  FD_SET(fd_, &set);
  const int rc = syscaller_->Select(fd_ + 1, &set, nullptr, nullptr, &tv);

  if (rc == 0) {
    LOG(ERROR) << __func__ << ": Timeout.";
    return false;
  }
  if (rc < 0) {
    PLOG(ERROR) << __func__ << ": Error calling `select()`";
    return false;
  }
  // Since only `fd_` is checked, rc > 0 means `fd_` must be ready.
  return true;
}

}  // namespace csme
}  // namespace trunks
