// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/scoped_key_handle.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "trunks/mock_tpm.h"
#include "trunks/tpm_generated.h"
#include "trunks/trunks_factory_for_test.h"

using testing::_;
using testing::DoAll;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;
using testing::SetArgPointee;
using testing::WithArgs;

namespace trunks {

// A test fixture for TpmState tests.
class ScopedKeyHandleTest : public testing::Test {
 public:
  ScopedKeyHandleTest() {}
  ~ScopedKeyHandleTest() override {}

  void SetUp() override { factory_.set_tpm(&mock_tpm_); }

 protected:
  TrunksFactoryForTest factory_;
  NiceMock<MockTpm> mock_tpm_;
};

TEST_F(ScopedKeyHandleTest, FlushHandle) {
  TPM_HANDLE handle = TPM_RH_FIRST;
  ScopedKeyHandle scoped_handle(factory_, handle);
  EXPECT_CALL(mock_tpm_, FlushContext(handle, _, _)).Times(1);
}

TEST_F(ScopedKeyHandleTest, GetTest) {
  TPM_HANDLE handle = TPM_RH_FIRST;
  ScopedKeyHandle scoped_handle(factory_, handle);
  EXPECT_EQ(handle, scoped_handle.get());
}

TEST_F(ScopedKeyHandleTest, ReleaseTest) {
  TPM_HANDLE handle = TPM_RH_FIRST;
  ScopedKeyHandle scoped_handle(factory_, handle);
  EXPECT_EQ(handle, scoped_handle.release());
  EXPECT_EQ(0u, scoped_handle.get());
}

TEST_F(ScopedKeyHandleTest, ResetAndFlush) {
  TPM_HANDLE old_handle = TPM_RH_FIRST;
  TPM_HANDLE new_handle = TPM_RH_NULL;
  ScopedKeyHandle scoped_handle(factory_, old_handle);
  EXPECT_EQ(old_handle, scoped_handle.get());
  EXPECT_CALL(mock_tpm_, FlushContext(old_handle, _, _)).Times(1);
  scoped_handle.reset(new_handle);
  EXPECT_EQ(new_handle, scoped_handle.get());
  EXPECT_CALL(mock_tpm_, FlushContext(new_handle, _, _)).Times(1);
}

TEST_F(ScopedKeyHandleTest, NullReset) {
  TPM_HANDLE handle = TPM_RH_FIRST;
  ScopedKeyHandle scoped_handle(factory_, handle);
  EXPECT_EQ(handle, scoped_handle.get());
  EXPECT_CALL(mock_tpm_, FlushContext(handle, _, _)).Times(1);
  scoped_handle.reset();
  EXPECT_EQ(0u, scoped_handle.get());
}

}  // namespace trunks
