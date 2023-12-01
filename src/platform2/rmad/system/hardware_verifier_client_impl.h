// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_SYSTEM_HARDWARE_VERIFIER_CLIENT_IMPL_H_
#define RMAD_SYSTEM_HARDWARE_VERIFIER_CLIENT_IMPL_H_

#include "rmad/system/hardware_verifier_client.h"

#include <string>
#include <vector>

#include <base/memory/scoped_refptr.h>
#include <dbus/bus.h>

namespace rmad {

class HardwareVerifierClientImpl : public HardwareVerifierClient {
 public:
  explicit HardwareVerifierClientImpl(const scoped_refptr<dbus::Bus>& bus);
  HardwareVerifierClientImpl(const HardwareVerifierClientImpl&) = delete;
  HardwareVerifierClientImpl& operator=(const HardwareVerifierClientImpl&) =
      delete;

  ~HardwareVerifierClientImpl() override = default;

  // TODO(chenghan): Use async call as hardware verification can take a while.
  bool GetHardwareVerificationResult(
      bool* is_compliant,
      std::vector<std::string>* error_strings) const override;

 private:
  // Owned by external D-Bus bus.
  dbus::ObjectProxy* proxy_;
};

}  // namespace rmad

#endif  // RMAD_SYSTEM_HARDWARE_VERIFIER_CLIENT_IMPL_H_
