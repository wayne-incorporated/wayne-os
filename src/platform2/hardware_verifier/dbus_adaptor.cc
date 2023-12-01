/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hardware_verifier/cli.h"
#include "hardware_verifier/dbus_adaptor.h"
#include "hardware_verifier/hardware_verifier.pb.h"
#include "hardware_verifier/hw_verification_report_getter.h"
#include "hardware_verifier/hw_verification_report_getter_impl.h"

namespace hardware_verifier {

namespace {

using ReportGetterErrorCode = HwVerificationReportGetter::ErrorCode;

}  // namespace

void DBusAdaptor::VerifyComponents(VerifyComponentsResponseCallback callback) {
  VerifyComponentsReply reply;
  ReportGetterErrorCode vr_getter_error;
  auto report = vr_getter_->Get("", "", &vr_getter_error);
  ErrorCode error;
  switch (vr_getter_error) {
    case ReportGetterErrorCode::kErrorCodeNoError:
      error = ERROR_OK;
      break;
    case ReportGetterErrorCode::kErrorCodeMissingDefaultHwVerificationSpecFile:
      error = ERROR_SKIPPED;
      break;
    case ReportGetterErrorCode::kErrorCodeInvalidHwVerificationSpecFile:
      error = ERROR_INVALID_HW_VERIFICATION_SPEC_FILE;
      break;
    case ReportGetterErrorCode::kErrorCodeInvalidProbeResultFile:
      error = ERROR_INVALID_PROBE_RESULT_FILE;
      break;
    case ReportGetterErrorCode::kErrorCodeProbeFail:
      error = ERROR_PROBE_FAIL;
      break;
    case ReportGetterErrorCode::
        kErrorCodeProbeResultHwVerificationSpecMisalignment:
      error = ERROR_PROBE_RESULT_HW_VERIFICATION_SPEC_MISALIGNMENT;
      break;
    default:
      error = ERROR_OTHER_ERROR;
      break;
  }
  reply.set_error(error);
  if (report)
    reply.mutable_hw_verification_report()->Swap(&*report);
  callback->Return(reply);
}

}  // namespace hardware_verifier
