/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hardware_verifier/hw_verification_report_getter_impl.h"

#include <memory>
#include <optional>
#include <utility>

#include <base/files/file_path.h>
#include <base/logging.h>

#include "hardware_verifier/hardware_verifier.pb.h"
#include "hardware_verifier/hw_verification_spec_getter_impl.h"
#include "hardware_verifier/observer.h"
#include "hardware_verifier/probe_result_getter_impl.h"
#include "hardware_verifier/verifier_impl.h"

namespace hardware_verifier {

HwVerificationReportGetterImpl::HwVerificationReportGetterImpl()
    : pr_getter_(std::make_unique<ProbeResultGetterImpl>()),
      vs_getter_(std::make_unique<HwVerificationSpecGetterImpl>()),
      verifier_(std::make_unique<VerifierImpl>()) {}

std::optional<HwVerificationReport> HwVerificationReportGetterImpl::Get(
    const base::StringPiece& probe_result_file,
    const base::StringPiece& hw_verification_spec_file,
    ErrorCode* out_error_code) const {
  DVLOG(1) << "Get the verification payload.";
  std::optional<HwVerificationSpec> hw_verification_spec;
  if (hw_verification_spec_file.empty()) {
    hw_verification_spec = vs_getter_->GetDefault();
    if (!hw_verification_spec) {
      if (out_error_code)
        *out_error_code =
            ErrorCode::kErrorCodeMissingDefaultHwVerificationSpecFile;
      return std::nullopt;
    }
  } else {
    hw_verification_spec =
        vs_getter_->GetFromFile(base::FilePath(hw_verification_spec_file));
    if (!hw_verification_spec) {
      if (out_error_code)
        *out_error_code = ErrorCode::kErrorCodeInvalidHwVerificationSpecFile;
      return std::nullopt;
    }
  }

  DVLOG(1) << "Get the probe result.";
  std::optional<runtime_probe::ProbeResult> probe_result;
  if (probe_result_file.empty()) {
    auto observer = Observer::GetInstance();
    observer->StartTimer(hardware_verifier::kMetricTimeToProbe);
    probe_result = pr_getter_->GetFromRuntimeProbe();
    observer->StopTimer(hardware_verifier::kMetricTimeToProbe);

    if (!probe_result) {
      if (out_error_code)
        *out_error_code = ErrorCode::kErrorCodeProbeFail;
      return std::nullopt;
    }
  } else {
    probe_result = pr_getter_->GetFromFile(base::FilePath(probe_result_file));
    if (!probe_result) {
      if (out_error_code)
        *out_error_code = ErrorCode::kErrorCodeInvalidProbeResultFile;
      return std::nullopt;
    }
  }

  DVLOG(1) << "Verify the probe result by the verification payload.";
  const auto verifier_result =
      verifier_->Verify(probe_result.value(), hw_verification_spec.value());
  if (out_error_code) {
    if (!verifier_result)
      *out_error_code =
          ErrorCode::kErrorCodeProbeResultHwVerificationSpecMisalignment;
    else
      *out_error_code = ErrorCode::kErrorCodeNoError;
  }
  return verifier_result;
}

}  // namespace hardware_verifier
