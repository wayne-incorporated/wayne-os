// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "attestation/server/attestation_flow.h"

#include <utility>

#include <base/check.h>
#include <base/check_op.h>

namespace attestation {

AttestationFlowData::AttestationFlowData(const EnrollRequest& request,
                                         EnrollCallback callback)
    : enroll_request_(request), enroll_callback_(std::move(callback)) {}
AttestationFlowData::AttestationFlowData(const GetCertificateRequest& request,
                                         GetCertificateCallback callback)
    : get_certificate_request_(request),
      get_certificate_callback_(std::move(callback)) {}

ACAType AttestationFlowData::aca_type() const {
  if (enroll_request_) {
    return enroll_request_->aca_type();
  }
  return get_certificate_request_->aca_type();
}

bool AttestationFlowData::shall_enroll() const {
  return enroll_request_ ||
         get_certificate_request_->shall_trigger_enrollment();
}

bool AttestationFlowData::shall_get_certificate() const {
  return static_cast<bool>(get_certificate_request_);
}

bool AttestationFlowData::forced_enrollment() const {
  return enroll_request_ && enroll_request_->forced();
}

bool AttestationFlowData::forced_get_certificate() const {
  return get_certificate_request_ && get_certificate_request_->forced();
}

const GetCertificateRequest& AttestationFlowData::get_certificate_request()
    const {
  return *get_certificate_request_;
}

std::string AttestationFlowData::username() const {
  DCHECK(get_certificate_request_);
  return get_certificate_request_->username();
}

std::string AttestationFlowData::key_label() const {
  DCHECK(get_certificate_request_);
  return get_certificate_request_->key_label();
}

void AttestationFlowData::ReturnStatus() {
  if (enroll_callback_) {
    EnrollReply reply;
    reply.set_status(status_);
    std::move(enroll_callback_).Run(reply);
  } else {
    DCHECK(get_certificate_callback_);
    GetCertificateReply reply;
    reply.set_status(status_);
    std::move(get_certificate_callback_).Run(reply);
  }
}

void AttestationFlowData::ReturnCertificate() {
  DCHECK(get_certificate_callback_);
  DCHECK_EQ(status_, STATUS_SUCCESS);
  GetCertificateReply reply;
  reply.set_status(STATUS_SUCCESS);
  reply.set_public_key(public_key_);
  reply.set_certificate(certificate_);
  reply.set_certified_key_credential(certified_key_credential_);
  reply.set_key_blob(key_blob_);
  std::move(get_certificate_callback_).Run(reply);
}

}  // namespace attestation
