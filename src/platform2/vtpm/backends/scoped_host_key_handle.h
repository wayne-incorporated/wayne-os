// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_BACKENDS_SCOPED_HOST_KEY_HANDLE_H_
#define VTPM_BACKENDS_SCOPED_HOST_KEY_HANDLE_H_

#include <optional>

#include "vtpm/backends/tpm_handle_manager.h"

namespace vtpm {

class TpmHandleManager;

// This class is a RAII-style host handle, which is managed by
// `TpmHandleManager`. It asks the set `TpmHandleManager` to flush the handle on
// the host TPM.
class ScopedHostKeyHandle {
 public:
  // Constructs a null instance that doesn't trigger anything upon destruction.
  ScopedHostKeyHandle();
  // Constructs an instance that asks `mgr` to flush `to_flush` upon
  // destruction. When calling `Get()`, `host_handle` shall be returned.
  ScopedHostKeyHandle(TpmHandleManager* mgr,
                      trunks::TPM_HANDLE host_handle,
                      trunks::TPM_HANDLE to_flush);
  // Constructs a instance that doesn't trigger anything upon destruction. When
  // calling `Get()`, `host_handle` shall be returned.
  ScopedHostKeyHandle(TpmHandleManager* mgr, trunks::TPM_HANDLE host_handle);
  ScopedHostKeyHandle(ScopedHostKeyHandle&& that);

  ~ScopedHostKeyHandle();
  // Non-copyable, but movable.
  ScopedHostKeyHandle& operator=(const ScopedHostKeyHandle&) = delete;
  ScopedHostKeyHandle& operator=(ScopedHostKeyHandle&& that);
  // Returns the host handle set during construction time.
  trunks::TPM_HANDLE Get() const;

 private:
  // Asks `tpm_handle_manager_` to flush the hold handle.
  void Flush();
  TpmHandleManager* tpm_handle_manager_;
  // The handle hold by `this` and managed by `tpm_handle_manager_`.
  trunks::TPM_HANDLE host_handle_;
  // The handle to flush. It is null if the handle should be flushed by the
  // guest.
  std::optional<trunks::TPM_HANDLE> to_flush_;
};

}  // namespace vtpm

#endif  // VTPM_BACKENDS_SCOPED_HOST_KEY_HANDLE_H_
