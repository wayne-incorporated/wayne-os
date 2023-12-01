// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "u2fd/fuzzers/fuzzed_allowlisting_util_factory.h"

#include <memory>
#include <optional>
#include <string>

#include <attestation/proto_bindings/interface.pb.h>

#include "u2fd/allowlisting_util.h"

namespace {

constexpr uint32_t kGetCertifiedG2fCertFailureRate = 10;

}  // namespace

namespace u2f {

std::unique_ptr<u2f::AllowlistingUtil>
FuzzedAllowlistingUtilFactory::CreateAllowlistingUtil() {
  return data_provider_->ConsumeBool()
             ? std::make_unique<u2f::AllowlistingUtil>(
                   [this](int g2f_cert_size) {
                     return this->GetCertifiedG2fCert(g2f_cert_size);
                   })
             : std::unique_ptr<u2f::AllowlistingUtil>(nullptr);
}

std::optional<attestation::GetCertifiedNvIndexReply>
FuzzedAllowlistingUtilFactory::GetCertifiedG2fCert(int g2f_cert_size) {
  if (data_provider_->ConsumeIntegralInRange<uint32_t>(0, 99) <
      kGetCertifiedG2fCertFailureRate) {
    return std::nullopt;
  }

  attestation::GetCertifiedNvIndexReply reply;
  std::string buf = data_provider_->ConsumeRandomLengthString();
  reply.ParseFromString(buf);
  return reply;
}

}  // namespace u2f
