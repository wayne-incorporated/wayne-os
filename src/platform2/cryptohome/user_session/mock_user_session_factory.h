// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_USER_SESSION_MOCK_USER_SESSION_FACTORY_H_
#define CRYPTOHOME_USER_SESSION_MOCK_USER_SESSION_FACTORY_H_

#include <memory>
#include <string>

#include "cryptohome/user_session/user_session.h"
#include "cryptohome/user_session/user_session_factory.h"

namespace cryptohome {

class MockUserSessionFactory : public UserSessionFactory {
 public:
  MockUserSessionFactory() = default;
  ~MockUserSessionFactory() override = default;

  MOCK_METHOD(std::unique_ptr<UserSession>,
              New,
              (const Username&, bool, bool),
              (override));
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_USER_SESSION_MOCK_USER_SESSION_FACTORY_H_
