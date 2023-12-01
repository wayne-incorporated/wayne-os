/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef HARDWARE_VERIFIER_HW_VERIFICATION_REPORT_GETTER_H_
#define HARDWARE_VERIFIER_HW_VERIFICATION_REPORT_GETTER_H_

#include <optional>

#include <base/strings/string_piece.h>

#include "hardware_verifier/hardware_verifier.pb.h"

namespace hardware_verifier {

// Interface that provides ways to retrieve |HwVerificationReport| messages.
class HwVerificationReportGetter {
 public:
  // The error code for Get().
  enum class ErrorCode {
    kErrorCodeNoError = 0,

    // Skipped the verifier since the default verificatiojn payload is not
    // found.
    kErrorCodeMissingDefaultHwVerificationSpecFile,

    // Failed to load the verification payload from either the default one or
    // the specific one.
    kErrorCodeInvalidHwVerificationSpecFile,

    // Failed to load the probe result from the specific file.
    kErrorCodeInvalidProbeResultFile,

    // Failed to load the probe result from |runtime_probe|.
    kErrorCodeProbeFail,

    // Content in the verification payload and the probe result are not matched
    // to each other.
    kErrorCodeProbeResultHwVerificationSpecMisalignment,
  };

  virtual ~HwVerificationReportGetter() = default;

  // Collects the probe result and the hardware verification spec, verifies
  // their content, and produces the |HwVerificationReport| message.
  //
  // @param probe_result_file: Path to the file that contains the probe result.
  //     If the string is empty, it invokes |runtime_probe| to get the probe
  //     result.
  // @param hw_verification_spec_file: Path to the file that contains the
  //     verification payload.  If the string is empty, it reads the default
  //     verification payload file in the rootfs.  See also
  //     |HwVerificationSpecGetter|.
  // @param out_error_code: The error code to the method.
  //
  // @return A |HwVerificationReport| message if it succeeds.
  virtual std::optional<HwVerificationReport> Get(
      const base::StringPiece& probe_result_file,
      const base::StringPiece& hw_verification_spec_file,
      ErrorCode* out_error_code) const = 0;
};

}  // namespace hardware_verifier

#endif  // HARDWARE_VERIFIER_HW_VERIFICATION_REPORT_GETTER_H_
