// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/supplicant/supplicant_eap_state_handler.h"

#include "shill/logging.h"
#include "shill/supplicant/wpa_supplicant.h"

#include <base/logging.h>

namespace shill {

SupplicantEAPStateHandler::SupplicantEAPStateHandler()
    : is_eap_in_progress_(false) {}

SupplicantEAPStateHandler::~SupplicantEAPStateHandler() = default;

bool SupplicantEAPStateHandler::ParseStatus(const std::string& status,
                                            const std::string& parameter,
                                            Service::ConnectFailure* failure) {
  if (status == WPASupplicant::kEAPStatusAcceptProposedMethod) {
    LOG(INFO) << "EAP: accepted method " << parameter;
  } else if (status == WPASupplicant::kEAPStatusCompletion) {
    if (parameter == WPASupplicant::kEAPParameterSuccess) {
      LOG(INFO) << "EAP: Completed authentication successfully.";
      is_eap_in_progress_ = false;
      return true;
    } else if (parameter == WPASupplicant::kEAPParameterFailure) {
      // If there was a TLS error, use this instead of the generic failure.
      if (tls_error_ == WPASupplicant::kEAPStatusLocalTLSAlert) {
        *failure = Service::kFailureEAPLocalTLS;
      } else if (tls_error_ == WPASupplicant::kEAPStatusRemoteTLSAlert) {
        *failure = Service::kFailureEAPRemoteTLS;
      } else {
        *failure = Service::kFailureEAPAuthentication;
      }
    } else {
      LOG(ERROR) << "EAP: Unexpected " << status << " parameter: " << parameter;
    }
  } else if (status == WPASupplicant::kEAPStatusLocalTLSAlert ||
             status == WPASupplicant::kEAPStatusRemoteTLSAlert) {
    tls_error_ = status;
  } else if (status == WPASupplicant::kEAPStatusRemoteCertificateVerification) {
    if (parameter == WPASupplicant::kEAPParameterSuccess) {
      LOG(INFO) << "EAP: Completed remote certificate verification.";
    } else {
      // wpa_supplicant doesn't currently have a verification failure
      // message.  We will instead get a RemoteTLSAlert above.
      LOG(ERROR) << "EAP: Unexpected " << status << " parameter: " << parameter;
    }
  } else if (status == WPASupplicant::kEAPStatusParameterNeeded) {
    if (parameter == WPASupplicant::kEAPRequestedParameterPin) {
      // wpa_supplicant could have erased the PIN.  Signal to WiFi that
      // it should supply one if possible.
      *failure = Service::kFailurePinMissing;
    } else {
      LOG(ERROR) << "EAP: Authentication aborted due to missing authentication "
                 << "parameter: " << parameter;
      *failure = Service::kFailureEAPAuthentication;
    }
  } else if (status == WPASupplicant::kEAPStatusStarted) {
    LOG(INFO) << "EAP: Authentication starting.";
    is_eap_in_progress_ = true;
  }

  return false;
}

void SupplicantEAPStateHandler::Reset() {
  is_eap_in_progress_ = false;
  tls_error_ = "";
}

}  // namespace shill
