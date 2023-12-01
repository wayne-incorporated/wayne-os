// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hermes/smdp.h"

#include <vector>

#include <base/functional/bind.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;

namespace hermes {

class SmdpFiTester {
 public:
  MOCK_METHOD(void,
              OnInitiateAuth,
              (const std::string&,
               const std::vector<uint8_t>&,
               const std::vector<uint8_t>&,
               const std::vector<uint8_t>&,
               const std::vector<uint8_t>&));
  MOCK_METHOD(void,
              OnAuthClient,
              (const std::string&,
               const std::vector<uint8_t>&,
               const std::vector<uint8_t>&,
               const std::vector<uint8_t>&,
               const std::vector<uint8_t>&));
  MOCK_METHOD(void, FakeError, (const std::vector<uint8_t>& error_data));
};

class SmdpTest : public testing::Test {
 public:
  SmdpTest() : smdp_("") {}
  ~SmdpTest() = default;

 protected:
  SmdpFiTester smdp_tester_;
  Smdp smdp_;
};

TEST_F(SmdpTest, InitiateAuthenticationTest) {
  const std::vector<uint8_t> fake_info1 = {0x00, 0x01};
  const std::vector<uint8_t> fake_challenge = {0x02, 0x03};
  EXPECT_CALL(smdp_tester_, OnInitiateAuth(_, _, _, _, _)).Times(1);
  EXPECT_CALL(smdp_tester_, FakeError(_)).Times(0);

  smdp_.InitiateAuthentication(fake_info1, fake_challenge,
                               base::BindOnce(&SmdpFiTester::OnInitiateAuth,
                                              base::Unretained(&smdp_tester_)),
                               base::BindOnce(&SmdpFiTester::FakeError,
                                              base::Unretained(&smdp_tester_)));
}

TEST_F(SmdpTest, AuthenticateClientTest) {
  const std::string transaction_id = "1";
  const std::vector<uint8_t> esim_data = {0, 1, 2, 3, 4};
  EXPECT_CALL(smdp_tester_, OnAuthClient(_, _, _, _, _)).Times(1);
  EXPECT_CALL(smdp_tester_, FakeError(_)).Times(0);

  smdp_.AuthenticateClient(transaction_id, esim_data,
                           base::BindOnce(&SmdpFiTester::OnAuthClient,
                                          base::Unretained(&smdp_tester_)),
                           base::BindOnce(&SmdpFiTester::FakeError,
                                          base::Unretained(&smdp_tester_)));
}

}  // namespace hermes
