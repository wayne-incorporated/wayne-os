// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_PCA_AGENT_SERVER_RESPONSE_WITH_VERIFIER_H_
#define ATTESTATION_PCA_AGENT_SERVER_RESPONSE_WITH_VERIFIER_H_

#include "attestation/pca_agent/server/pca_agent_service.h"

#include <memory>
#include <string>

#include <base/functional/bind.h>
#include <brillo/dbus/dbus_method_response.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace attestation {
namespace pca_agent {

using ::testing::_;
using ::testing::Invoke;

template <typename ReplyType, typename Verifier>
class ResponseWithVerifier
    : public brillo::dbus_utils::DBusMethodResponse<ReplyType> {
 public:
  explicit ResponseWithVerifier(Verifier&& v)
      : brillo::dbus_utils::DBusMethodResponse<ReplyType>(
            /*method_call=*/nullptr,
            base::BindOnce([](std::unique_ptr<dbus::Response> response) {
              FAIL() << "The sender shouldn't have been called.";
            })),
        verifier_(v) {
    // By default, |Return| calls |Verify|.
    ON_CALL(*this, Return(_)).WillByDefault(Invoke(verifier_));
    EXPECT_CALL(*this, Return(_)).Times(1);
  }
  ~ResponseWithVerifier() = default;
  // Makes |Return| a mock mothod so we can set EXPECT_* to it.
  MOCK_METHOD(void, Return, (const ReplyType& reply), (override));

 private:
  Verifier verifier_;
};

template <typename ReplyType, typename Verifier>
std::unique_ptr<ResponseWithVerifier<ReplyType, Verifier>>
MakeResponseWithVerifier(Verifier&& v) {
  return std::make_unique<ResponseWithVerifier<ReplyType, Verifier>>(v);
}

}  // namespace pca_agent
}  // namespace attestation

#endif  // ATTESTATION_PCA_AGENT_SERVER_RESPONSE_WITH_VERIFIER_H_
