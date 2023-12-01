// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_TEST_UTILS_TPM1_TEST_FIXTURE_H_
#define LIBHWSEC_TEST_UTILS_TPM1_TEST_FIXTURE_H_

#include <memory>

#include <gtest/gtest.h>

#include "libhwsec/hwsec_export.h"
#include "libhwsec/overalls/mock_overalls.h"

// ON_CALL_OVERALLS and EXPECT_CALL_OVERALLS are meant to be used for specifying
// ON_CALL and EXPECT_CALL for the |MockOveralls| injected to the
// |OverallsSingleton|. It determines the |MockOveralls| objects automatically
// so the users only have to specify the API name and behaviors.
// Example usage:
//
// void SetUp() override {
//     ON_CALL_OVERALLS(Ospi_Context_Create(_))
//     .WillByDefault(Return(TSS_SUCCESS)));
//
// EXPECT_CALL_OVERALLS(Ospi_Context_Create(_))
//     .WillOnce(Return(TSP_ERROR(TSS_E_INTERNAL_ERROR)));
#define ON_CALL_OVERALLS(call) ON_CALL((*mock_overalls_), call)
#define EXPECT_CALL_OVERALLS(call) EXPECT_CALL((*mock_overalls_), call)

namespace hwsec {

// Represents the types of MockOveralls; see the comment inlined below.
enum class MOCK_OVERALLS_TYPE {
  // NiceMock<MockOveralls>
  NICE,
  // MockOveralls
  PLAIN,
  // StrictMock<MockOveralls>
  STRICT,
};

// A test fixture that implements the common setup for TPM1.2
class HWSEC_EXPORT Tpm1HwsecTest : public ::testing::Test {
 public:
  // Constructs the test fixture with default setup; specifically, the type of
  // |MockOveralls| will be a NiceMock. See the delegated constructor below for
  // more information.
  Tpm1HwsecTest();
  // Constructs the test fixture instructed by the input parameters. The
  // MockOveralls is injected into the singleton during the test according to
  // |mock_overalls_type|. See |MOCK_OVERALLS_TYPE| for reference.
  explicit Tpm1HwsecTest(MOCK_OVERALLS_TYPE mock_overalls_type);
  ~Tpm1HwsecTest() override;

 protected:
  // The mock instance of |Overalls| and the backup  of normal |Overalls| are
  // defined below.
  std::unique_ptr<overalls::MockOveralls> mock_overalls_;
  overalls::Overalls* original_overalls_{nullptr};
};

}  // namespace hwsec

#endif  // LIBHWSEC_TEST_UTILS_TPM1_TEST_FIXTURE_H_
