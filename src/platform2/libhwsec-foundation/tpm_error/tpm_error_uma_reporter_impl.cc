// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/tpm_error/tpm_error_uma_reporter_impl.h"

#include <string>

#include <base/logging.h>

#include "libhwsec-foundation/tpm_error/tpm_error_constants.h"
#include "libhwsec-foundation/tpm_error/tpm_error_data.h"
#include "libhwsec-foundation/tpm_error/tpm_error_metrics_constants.h"

namespace hwsec_foundation {

namespace {

std::string ClientIDToClientName(TpmMetricsClientID id) {
  switch (id) {
    case TpmMetricsClientID::kUnknown:
      return "Unknown";
    case TpmMetricsClientID::kCryptohome:
      return "Cryptohome";
    case TpmMetricsClientID::kAttestation:
      return "Attestation";
    case TpmMetricsClientID::kTpmManager:
      return "TpmManager";
    case TpmMetricsClientID::kChaps:
      return "Chaps";
    case TpmMetricsClientID::kVtpm:
      return "Vtpm";
    case TpmMetricsClientID::kU2f:
      return "U2f";
    case TpmMetricsClientID::kTrunksSend:
      return "TrunksSend";
  }
}

}  // namespace

TpmErrorUmaReporterImpl::TpmErrorUmaReporterImpl(
    MetricsLibraryInterface* metrics)
    : metrics_(metrics) {}

void TpmErrorUmaReporterImpl::Report(const TpmErrorData& data) {
  switch (data.response) {
    case kTpm1AuthFailResponse:
      metrics_->SendSparseToUMA(kTpm1AuthFailName, data.command);
      break;
    case kTpm1Auth2FailResponse:
      metrics_->SendSparseToUMA(kTpm1Auth2FailName, data.command);
      break;
    default:
      break;
  }
}

bool TpmErrorUmaReporterImpl::ReportCommandAndResponse(
    const std::string& metrics_prefix, const TpmErrorData& data) {
  TpmMetricsClientID client_id = GetTpmMetricsClientID();
  // Returns false since the command and response is invalid.
  if (data.command > 0x0FFF || data.response > 0xFFFF) {
    return false;
  }
  std::string client_name = ClientIDToClientName(client_id);
  std::string metrics_name = metrics_prefix + '.' + client_name;
  uint32_t metrics_value = (data.command << 16) + (data.response & 0xFFFF);
  metrics_->SendSparseToUMA(metrics_name, metrics_value);
  return true;
}

bool TpmErrorUmaReporterImpl::ReportTpm1CommandAndResponse(
    const TpmErrorData& data) {
  return ReportCommandAndResponse(kTpm1CommandAndResponsePrefix, data);
}

bool TpmErrorUmaReporterImpl::ReportTpm2CommandAndResponse(
    const TpmErrorData& data) {
  return ReportCommandAndResponse(kTpm2CommandAndResponsePrefix, data);
}

}  // namespace hwsec_foundation
