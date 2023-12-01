// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/policy_service_util.h"

#include <string>

#include <base/types/expected.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "bindings/device_management_backend.pb.h"
#include "crypto/signature_verifier.h"

namespace em = enterprise_management;

using ::testing::_;

namespace login_manager {
struct MapSignatureTypeTestCase {
  em::PolicyFetchRequest::SignatureType em_signature_type;
  crypto::SignatureVerifier::SignatureAlgorithm expected_signature_type;
};

class MapSignatureTypeTest
    : public ::testing::Test,
      public testing::WithParamInterface<MapSignatureTypeTestCase> {};

TEST_P(MapSignatureTypeTest, MapSignatureTypeSuccess) {
  const MapSignatureTypeTestCase& test_case = GetParam();

  base::expected<crypto::SignatureVerifier::SignatureAlgorithm, std::string>
      mapped_signature_type = MapSignatureType(test_case.em_signature_type);

  ASSERT_TRUE(mapped_signature_type.has_value());
  EXPECT_EQ(mapped_signature_type.value(), test_case.expected_signature_type);
}

TEST_F(MapSignatureTypeTest, MapSignatureTypeFailure) {
  base::expected<crypto::SignatureVerifier::SignatureAlgorithm, std::string>
      mapped_signature_type = MapSignatureType(em::PolicyFetchRequest::NONE);

  EXPECT_FALSE(mapped_signature_type.has_value());
}

INSTANTIATE_TEST_SUITE_P(SignatureAlgorithm,
                         MapSignatureTypeTest,
                         ::testing::ValuesIn<MapSignatureTypeTestCase>(
                             {{em::PolicyFetchRequest::SHA1_RSA,
                               crypto::SignatureVerifier::RSA_PKCS1_SHA1},
                              {em::PolicyFetchRequest::SHA256_RSA,
                               crypto::SignatureVerifier::RSA_PKCS1_SHA256}}));
}  // namespace login_manager
