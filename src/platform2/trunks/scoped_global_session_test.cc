// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/scoped_global_session.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "trunks/mock_hmac_session.h"
#include "trunks/mock_session_manager.h"
#include "trunks/trunks_factory_for_test.h"

using testing::_;
using testing::NiceMock;
using testing::Return;
using testing::StrictMock;

namespace trunks {

class ScopedGlobalHmacSessionTest : public testing::Test {
 public:
  void SetUp() override {
    factory_.set_session_manager(&session_manager_);
    factory_.set_hmac_session(&hmac_session_);
  }

 protected:
  StrictMock<MockHmacSession> hmac_session_;
  NiceMock<MockSessionManager> session_manager_;
  TrunksFactoryForTest factory_;
};

#ifdef TRUNKS_USE_PER_OP_SESSIONS
TEST_F(ScopedGlobalHmacSessionTest, HmacSessionSuccessNew) {
  for (bool salted : {true, false}) {
    for (bool enable_encryption : {true, false}) {
      std::unique_ptr<HmacSession> global_session;
      EXPECT_EQ(nullptr, global_session);
      {
        EXPECT_CALL(hmac_session_,
                    StartUnboundSession(salted, enable_encryption))
            .WillOnce(Return(TPM_RC_SUCCESS));
        ScopedGlobalHmacSession scope(&factory_, salted, enable_encryption,
                                      &global_session);
        EXPECT_NE(nullptr, global_session);
      }
      EXPECT_EQ(nullptr, global_session);
    }
  }
}

TEST_F(ScopedGlobalHmacSessionTest, HmacSessionFailureNew) {
  for (bool salted : {true, false}) {
    for (bool enable_encryption : {true, false}) {
      std::unique_ptr<HmacSession> global_session;
      {
        EXPECT_CALL(hmac_session_,
                    StartUnboundSession(salted, enable_encryption))
            .WillOnce(Return(TPM_RC_FAILURE));
        ScopedGlobalHmacSession scope(&factory_, salted, enable_encryption,
                                      &global_session);
        EXPECT_EQ(nullptr, global_session);
      }
      EXPECT_EQ(nullptr, global_session);
    }
  }
}

TEST_F(ScopedGlobalHmacSessionTest, HmacSessionSuccessExisting) {
  for (bool salted : {true, false}) {
    for (bool enable_encryption : {true, false}) {
      auto old_hmac_session = new StrictMock<MockHmacSession>();
      std::unique_ptr<HmacSession> global_session(old_hmac_session);
      EXPECT_EQ(old_hmac_session, global_session.get());
      {
        EXPECT_CALL(hmac_session_,
                    StartUnboundSession(salted, enable_encryption))
            .WillOnce(Return(TPM_RC_SUCCESS));
        ScopedGlobalHmacSession scope(&factory_, salted, enable_encryption,
                                      &global_session);
        EXPECT_NE(nullptr, global_session);
        EXPECT_NE(old_hmac_session, global_session.get());
      }
      EXPECT_EQ(nullptr, global_session);
    }
  }
}

TEST_F(ScopedGlobalHmacSessionTest, HmacSessionFailureExisting) {
  for (bool salted : {true, false}) {
    for (bool enable_encryption : {true, false}) {
      auto old_hmac_session = new StrictMock<MockHmacSession>();
      std::unique_ptr<HmacSession> global_session(old_hmac_session);
      EXPECT_EQ(old_hmac_session, global_session.get());
      {
        EXPECT_CALL(hmac_session_,
                    StartUnboundSession(salted, enable_encryption))
            .WillOnce(Return(TPM_RC_FAILURE));
        ScopedGlobalHmacSession scope(&factory_, salted, enable_encryption,
                                      &global_session);
        EXPECT_EQ(nullptr, global_session);
      }
      EXPECT_EQ(nullptr, global_session);
    }
  }
}
#else  // TRUNKS_USE_PER_OP_SESSIONS
TEST_F(ScopedGlobalHmacSessionTest, HmacSessionNew) {
  for (bool salted : {true, false}) {
    for (bool enable_encryption : {true, false}) {
      std::unique_ptr<HmacSession> global_session;
      {
        ScopedGlobalHmacSession scope(&factory_, salted, enable_encryption,
                                      &global_session);
        EXPECT_EQ(nullptr, global_session);
      }
      EXPECT_EQ(nullptr, global_session);
    }
  }
}

TEST_F(ScopedGlobalHmacSessionTest, HmacSessionExisting) {
  for (bool salted : {true, false}) {
    for (bool enable_encryption : {true, false}) {
      auto old_hmac_session = new StrictMock<MockHmacSession>();
      std::unique_ptr<HmacSession> global_session(old_hmac_session);
      {
        ScopedGlobalHmacSession scope(&factory_, salted, enable_encryption,
                                      &global_session);
        EXPECT_EQ(old_hmac_session, global_session.get());
      }
      EXPECT_EQ(old_hmac_session, global_session.get());
    }
  }
}
#endif  // TRUNKS_USE_PER_OP_SESSIONS

}  // namespace trunks
