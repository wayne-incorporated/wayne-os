// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include "biod/biometrics_manager.h"
#include "biod/mock_biometrics_manager.h"
#include "biod/session.h"

#include <gtest/gtest.h>

namespace biod {
namespace {

TEST(SessionTest, EmptySessionError) {
  BiometricsManager::EnrollSession enroll_session;
  EXPECT_TRUE(enroll_session.error().empty());
}

TEST(SessionTest, SessionError) {
  std::string session_error = "HW is not available";
  BiometricsManager::EnrollSession enroll_session;
  enroll_session.set_error(session_error);
  EXPECT_EQ(enroll_session.error(), session_error);
}

TEST(SessionTest, MoveConstructor) {
  MockBiometricsManager mock_biometrics_manager;
  const std::string kSessionError = "HW is not available";

  BiometricsManager::EnrollSession enroll_session_1(
      mock_biometrics_manager.session_weak_factory_.GetWeakPtr());
  enroll_session_1.set_error(kSessionError);

  ASSERT_TRUE(enroll_session_1);

  BiometricsManager::EnrollSession enroll_session_2(
      std::move(enroll_session_1));
  EXPECT_TRUE(enroll_session_1.error().empty());
  EXPECT_EQ(enroll_session_2.error(), kSessionError);
  EXPECT_FALSE(enroll_session_1);
  EXPECT_TRUE(enroll_session_2);
}

TEST(SessionTest, MoveAssignment) {
  MockBiometricsManager mock_biometrics_manager;
  const std::string kSessionError = "HW is not available";

  BiometricsManager::EnrollSession enroll_session_1(
      mock_biometrics_manager.session_weak_factory_.GetWeakPtr());
  enroll_session_1.set_error(kSessionError);
  BiometricsManager::EnrollSession enroll_session_2;

  ASSERT_TRUE(enroll_session_1);
  ASSERT_FALSE(enroll_session_2);

  enroll_session_2 = std::move(enroll_session_1);
  EXPECT_TRUE(enroll_session_1.error().empty());
  EXPECT_EQ(enroll_session_2.error(), kSessionError);
  EXPECT_FALSE(enroll_session_1);
  EXPECT_TRUE(enroll_session_2);
}

TEST(SessionTest, EndValidSession) {
  MockBiometricsManager mock_biometrics_manager;
  const std::string kSessionError = "HW is not available";

  BiometricsManager::EnrollSession enroll_session_1(
      mock_biometrics_manager.session_weak_factory_.GetWeakPtr());
  enroll_session_1.set_error(kSessionError);

  ASSERT_TRUE(enroll_session_1);
  ASSERT_EQ(enroll_session_1.error(), kSessionError);

  enroll_session_1.End();

  EXPECT_FALSE(enroll_session_1);
  EXPECT_TRUE(enroll_session_1.error().empty());
}

TEST(SessionTest, EndInvalidSession) {
  const std::string kSessionError = "HW is not available";

  BiometricsManager::EnrollSession enroll_session_1;
  enroll_session_1.set_error(kSessionError);

  ASSERT_FALSE(enroll_session_1);
  ASSERT_EQ(enroll_session_1.error(), kSessionError);

  enroll_session_1.End();

  EXPECT_FALSE(enroll_session_1);
  EXPECT_TRUE(enroll_session_1.error().empty());
}

}  // namespace
}  // namespace biod
