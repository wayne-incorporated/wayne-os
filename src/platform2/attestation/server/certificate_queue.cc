// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "attestation/server/certificate_queue.h"

#include <string>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>

namespace attestation {

namespace {

// The URL query style separator used to concat username and the key label.
constexpr char kNameLabelSeparator[] = "?key_label=";

// Compares all the field other than |aca_type|, |username|, and |key_label| of
// |request1| and |request2|; returns |false| if any mismatch.
bool HaveConsistentConfigs(const GetCertificateRequest& request1,
                           const GetCertificateRequest& request2) {
  DCHECK_EQ(request1.username(), request2.username());
  DCHECK_EQ(request1.aca_type(), request2.aca_type());
  DCHECK_EQ(request1.key_label(), request2.key_label());
  return request1.certificate_profile() == request2.certificate_profile() &&
         request1.request_origin() == request2.request_origin() &&
         request1.key_type() == request2.key_type();
}

}  // namespace

CertificateQueue::CertificateQueue(size_t alias_limit)
    : alias_limit_(alias_limit) {}

CertificateQueue::PushResult CertificateQueue::Push(
    const std::shared_ptr<AttestationFlowData>& data) {
  DCHECK(data->shall_get_certificate());
  auto& aliases = table_[data];
  if (aliases.size() == alias_limit_) {
    return PushResult::kAliasLimit;
  }
  // Checks the consistency of the cert requests.
  if (!aliases.empty() &&
      !HaveConsistentConfigs(aliases[0]->get_certificate_request(),
                             data->get_certificate_request())) {
    return PushResult::kInconsistentConfig;
  }
  aliases.push_back(data);
  return PushResult::kSuccess;
}

bool CertificateQueue::HasAnyAlias(
    const std::shared_ptr<AttestationFlowData>& data) const {
  auto iter = table_.find(data);
  return iter != table_.end();
}

std::vector<std::shared_ptr<AttestationFlowData>>
CertificateQueue::PopAllAliases(
    const std::shared_ptr<AttestationFlowData>& data) {
  auto iter = table_.find(data);
  if (iter == table_.end()) {
    return {};
  }
  // Swaps out the aliases and erases the entry.
  auto aliases = std::move(iter->second);
  table_.erase(iter);
  return aliases;
}

size_t CertificateQueue::DataHash::operator()(
    const std::shared_ptr<AttestationFlowData>& data) const {
  // By design, we don't hash |aca_type|.
  return std::hash<std::string>()(data->username() + kNameLabelSeparator +
                                  data->key_label());
}

bool CertificateQueue::DataEqual::operator()(
    const std::shared_ptr<AttestationFlowData>& data1,
    const std::shared_ptr<AttestationFlowData>& data2) const {
  return data1->aca_type() == data2->aca_type() &&
         data1->username() == data2->username() &&
         data1->key_label() == data2->key_label();
}

}  // namespace attestation
