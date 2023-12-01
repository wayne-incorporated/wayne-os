/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef HARDWARE_VERIFIER_HW_VERIFICATION_REPORT_GETTER_IMPL_H_
#define HARDWARE_VERIFIER_HW_VERIFICATION_REPORT_GETTER_IMPL_H_

#include <memory>
#include <optional>
#include <utility>

#include <base/strings/string_piece.h>

#include "hardware_verifier/hardware_verifier.pb.h"
#include "hardware_verifier/hw_verification_report_getter.h"
#include "hardware_verifier/hw_verification_spec_getter.h"
#include "hardware_verifier/probe_result_getter.h"
#include "hardware_verifier/verifier.h"

namespace hardware_verifier {

// The actual implementation to the |HwVerificationReportGetter|.
class HwVerificationReportGetterImpl : public HwVerificationReportGetter {
 public:
  HwVerificationReportGetterImpl();
  HwVerificationReportGetterImpl(const HwVerificationReportGetterImpl&) =
      delete;
  HwVerificationReportGetterImpl& operator=(
      const HwVerificationReportGetterImpl&) = delete;

  std::optional<HwVerificationReport> Get(
      const base::StringPiece& probe_result_file,
      const base::StringPiece& hw_verification_spec_file,
      ErrorCode* error_code) const override;

 protected:
  // This constructor is reserved only for testing.
  explicit HwVerificationReportGetterImpl(
      std::unique_ptr<ProbeResultGetter> pr_getter,
      std::unique_ptr<HwVerificationSpecGetter> vs_getter,
      std::unique_ptr<Verifier> verifier)
      : pr_getter_(std::move(pr_getter)),
        vs_getter_(std::move(vs_getter)),
        verifier_(std::move(verifier)) {}

 private:
  std::unique_ptr<ProbeResultGetter> pr_getter_;
  std::unique_ptr<HwVerificationSpecGetter> vs_getter_;
  std::unique_ptr<Verifier> verifier_;
};

}  // namespace hardware_verifier

#endif  // HARDWARE_VERIFIER_HW_VERIFICATION_REPORT_GETTER_IMPL_H_
