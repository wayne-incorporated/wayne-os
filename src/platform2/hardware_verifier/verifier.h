/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef HARDWARE_VERIFIER_VERIFIER_H_
#define HARDWARE_VERIFIER_VERIFIER_H_

#include <runtime_probe/proto_bindings/runtime_probe.pb.h>

#include <optional>

#include "hardware_verifier/hardware_verifier.pb.h"

namespace hardware_verifier {

// Interface for the class that verifies if the probe result is compliant.
class Verifier {
 public:
  virtual ~Verifier() = default;

  // Verifies if the given probe result matches the verification spec or not.
  //
  // @param probe_result: The probe result to be checked.
  // @param hw_verification_spec: The device spec which contains the
  //     expectation of the probe result.
  //
  // @return Instance of |HwVerificationReport| if it succeeds.
  virtual std::optional<HwVerificationReport> Verify(
      const runtime_probe::ProbeResult& probe_result,
      const HwVerificationSpec& hw_verification_spec) const = 0;
};

}  // namespace hardware_verifier

#endif  // HARDWARE_VERIFIER_VERIFIER_H_
