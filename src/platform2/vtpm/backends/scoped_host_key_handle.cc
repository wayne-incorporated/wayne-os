// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/backends/scoped_host_key_handle.h"

#include <utility>

#include <trunks/tpm_generated.h>

namespace vtpm {

ScopedHostKeyHandle::ScopedHostKeyHandle()
    : ScopedHostKeyHandle(nullptr, trunks::TPM_HANDLE(), trunks::TPM_HANDLE()) {
}

ScopedHostKeyHandle::ScopedHostKeyHandle(TpmHandleManager* mgr,
                                         trunks::TPM_HANDLE host_handle,
                                         trunks::TPM_HANDLE to_flush)
    : tpm_handle_manager_(mgr),
      host_handle_(host_handle),
      to_flush_(to_flush) {}

ScopedHostKeyHandle::ScopedHostKeyHandle(TpmHandleManager* mgr,
                                         trunks::TPM_HANDLE host_handle)
    : tpm_handle_manager_(mgr), host_handle_(host_handle) {}

ScopedHostKeyHandle::ScopedHostKeyHandle(ScopedHostKeyHandle&& that) {
  *this = std::move(that);
}

ScopedHostKeyHandle::~ScopedHostKeyHandle() {
  Flush();
}

ScopedHostKeyHandle& ScopedHostKeyHandle::operator=(
    ScopedHostKeyHandle&& that) {
  Flush();
  tpm_handle_manager_ = that.tpm_handle_manager_;
  host_handle_ = that.host_handle_;
  to_flush_ = that.to_flush_;

  that.tpm_handle_manager_ = nullptr;
  that.host_handle_ = trunks::TPM_HANDLE();
  that.to_flush_.reset();
  return *this;
}

trunks::TPM_HANDLE ScopedHostKeyHandle::Get() const {
  return host_handle_;
}

void ScopedHostKeyHandle::Flush() {
  if (tpm_handle_manager_ == nullptr || !to_flush_.has_value()) {
    return;
  }
  tpm_handle_manager_->FlushHostHandle(*to_flush_);
}

}  // namespace vtpm
