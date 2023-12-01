// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_DA_RESET_DA_RESETTER_H_
#define LIBHWSEC_FOUNDATION_DA_RESET_DA_RESETTER_H_

#include <memory>

#include <metrics/metrics_library.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>

// This has to go after tpm_manager.pb.h.
#include <tpm_manager-client/tpm_manager/dbus-proxies.h>

#include "libhwsec-foundation/hwsec-foundation_export.h"

namespace hwsec_foundation {

// `DAResetter` resets the DA counter. The underlying implementation uses tpm
// manager D-Bus proxy.
class HWSEC_FOUNDATION_EXPORT DAResetter {
 public:
  DAResetter();
  explicit DAResetter(
      std::unique_ptr<org::chromium::TpmManagerProxyInterface> proxy);
  ~DAResetter() = default;

  // Not copyable or movable.
  DAResetter(const DAResetter&) = delete;
  DAResetter& operator=(const DAResetter&) = delete;
  DAResetter(DAResetter&&) = delete;
  DAResetter& operator=(DAResetter&&) = delete;

  // Resets the DA counter of the TPM; returns `false` if the operation fails.
  // Otherwise, returns `true`.
  bool ResetDictionaryAttackLock();

 private:
  std::unique_ptr<org::chromium::TpmManagerProxyInterface> proxy_;
};

}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_DA_RESET_DA_RESETTER_H_
