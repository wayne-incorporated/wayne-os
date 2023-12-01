// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/scoped_key_handle.h"

#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/logging.h>

#include "trunks/error_codes.h"
#include "trunks/tpm_generated.h"

namespace {

const trunks::TPM_HANDLE kInvalidHandle = 0;

}  // namespace

namespace trunks {

ScopedKeyHandle::ScopedKeyHandle(const TrunksFactory& factory)
    : factory_(factory), handle_(kInvalidHandle) {}

ScopedKeyHandle::ScopedKeyHandle(const TrunksFactory& factory,
                                 TPM_HANDLE handle)
    : factory_(factory), handle_(handle) {}

ScopedKeyHandle::~ScopedKeyHandle() {
  if (handle_ != kInvalidHandle) {
    FlushHandleContext(handle_);
  }
}

TPM_HANDLE ScopedKeyHandle::release() {
  TPM_HANDLE tmp_handle = handle_;
  handle_ = kInvalidHandle;
  return tmp_handle;
}

void ScopedKeyHandle::reset(TPM_HANDLE new_handle) {
  TPM_HANDLE tmp_handle = handle_;
  handle_ = new_handle;
  if (tmp_handle != kInvalidHandle) {
    FlushHandleContext(tmp_handle);
  }
}

void ScopedKeyHandle::reset() {
  reset(kInvalidHandle);
}

TPM_HANDLE* ScopedKeyHandle::ptr() {
  return &handle_;
}

TPM_HANDLE ScopedKeyHandle::get() const {
  return handle_;
}

void ScopedKeyHandle::set_synchronized(bool sync) {
  sync_ = sync;
}

void ScopedKeyHandle::FlushHandleContext(TPM_HANDLE handle) {
  if (sync_) {
    TPM_RC result = factory_.GetTpm()->FlushContextSync(handle, nullptr);
    if (result) {
      LOG(WARNING) << "Error closing handle: " << handle << " : "
                   << GetErrorString(result);
    }
  } else {
    factory_.GetTpm()->FlushContext(
        handle, nullptr,
        base::BindRepeating(
            [](TPM_HANDLE handle, TPM_RC result) {
              if (result) {
                LOG(WARNING) << "Error closing handle: " << handle << " : "
                             << GetErrorString(result);
              }
            },
            handle));
  }
}

}  // namespace trunks
