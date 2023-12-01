// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/user_session/user_session_map.h"

#include <memory>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cryptohome/mock_credential_verifier.h"
#include "cryptohome/user_session/mock_user_session.h"
#include "cryptohome/user_session/user_session.h"

namespace cryptohome {
namespace {

using ::testing::IsNull;
using ::testing::IsTrue;
using ::testing::Not;
using ::testing::Pair;
using ::testing::UnorderedElementsAre;

// Helper utility for making a stub verifier with a given label. Returns a
// "unique_ptr, ptr" pair so that tests that need to hand over ownership but
// hold on to a pointer can easily do so. Usually used as:
//
//   auto [verifier, ptr] = MakeTestVerifier("label")
std::pair<std::unique_ptr<CredentialVerifier>, CredentialVerifier*>
MakeTestVerifier(std::string label) {
  auto owned_ptr = std::make_unique<MockCredentialVerifier>(
      AuthFactorType::kPassword, std::move(label),
      AuthFactorMetadata{.metadata = auth_factor::PasswordMetadata()});
  auto* unowned_ptr = owned_ptr.get();
  return {std::move(owned_ptr), unowned_ptr};
}

std::vector<std::pair<Username, const UserSession*>> GetSessionItems(
    const UserSessionMap& session_map) {
  std::vector<std::pair<Username, const UserSession*>> items;
  for (const auto& [account_id, session] : session_map) {
    items.emplace_back(account_id, &session);
  }
  return items;
}

class UserSessionMapTest : public testing::Test {
 protected:
  // Constants for use in testing. These are non-static because Username cannot
  // be safely used as constexpr, but they are logically global constants.
  const Username kUsername1{"foo1@bar.com"};
  const Username kUsername2{"foo2@bar.com"};

  // Returns a const-ref to the test object. Used for testing const methods.
  const UserSessionMap& const_session_map() const { return session_map_; }

  UserSessionMap session_map_;
};

TEST_F(UserSessionMapTest, InitialEmpty) {
  EXPECT_TRUE(session_map_.empty());
  EXPECT_EQ(session_map_.size(), 0);
  EXPECT_EQ(session_map_.begin(), session_map_.end());
  EXPECT_EQ(session_map_.Find(kUsername1), nullptr);
  EXPECT_EQ(session_map_.Find(kUsername2), nullptr);
  EXPECT_EQ(const_session_map().Find(kUsername1), nullptr);
  EXPECT_EQ(const_session_map().Find(kUsername2), nullptr);
}

TEST_F(UserSessionMapTest, AddOne) {
  auto session = std::make_unique<MockUserSession>();
  const UserSession* session_ptr = session.get();

  EXPECT_TRUE(session_map_.Add(kUsername1, std::move(session)));

  EXPECT_FALSE(session_map_.empty());
  EXPECT_EQ(session_map_.size(), 1);
  EXPECT_THAT(GetSessionItems(session_map_),
              UnorderedElementsAre(Pair(kUsername1, session_ptr)));
  EXPECT_EQ(session_map_.Find(kUsername1), session_ptr);
  EXPECT_EQ(session_map_.Find(kUsername2), nullptr);
  EXPECT_EQ(const_session_map().Find(kUsername1), session_ptr);
  EXPECT_EQ(const_session_map().Find(kUsername2), nullptr);
}

TEST_F(UserSessionMapTest, AddTwo) {
  auto session1 = std::make_unique<MockUserSession>();
  const UserSession* session1_ptr = session1.get();
  auto session2 = std::make_unique<MockUserSession>();
  const UserSession* session2_ptr = session2.get();

  EXPECT_TRUE(session_map_.Add(kUsername1, std::move(session1)));
  EXPECT_TRUE(session_map_.Add(kUsername2, std::move(session2)));

  EXPECT_FALSE(session_map_.empty());
  EXPECT_EQ(session_map_.size(), 2);
  EXPECT_THAT(GetSessionItems(session_map_),
              UnorderedElementsAre(Pair(kUsername1, session1_ptr),
                                   Pair(kUsername2, session2_ptr)));
  EXPECT_EQ(session_map_.Find(kUsername1), session1_ptr);
  EXPECT_EQ(session_map_.Find(kUsername2), session2_ptr);
  EXPECT_EQ(const_session_map().Find(kUsername1), session1_ptr);
  EXPECT_EQ(const_session_map().Find(kUsername2), session2_ptr);
}

TEST_F(UserSessionMapTest, AddDuplicate) {
  auto session1 = std::make_unique<MockUserSession>();
  const UserSession* session1_ptr = session1.get();
  EXPECT_TRUE(session_map_.Add(kUsername1, std::move(session1)));

  EXPECT_FALSE(
      session_map_.Add(kUsername1, std::make_unique<MockUserSession>()));

  EXPECT_EQ(session_map_.size(), 1);
  EXPECT_EQ(session_map_.Find(kUsername1), session1_ptr);
}

TEST_F(UserSessionMapTest, RemoveSingle) {
  EXPECT_TRUE(
      session_map_.Add(kUsername1, std::make_unique<MockUserSession>()));

  EXPECT_TRUE(session_map_.Remove(kUsername1));

  EXPECT_EQ(session_map_.size(), 0);
  EXPECT_EQ(session_map_.Find(kUsername1), nullptr);
  EXPECT_EQ(const_session_map().Find(kUsername1), nullptr);
}

TEST_F(UserSessionMapTest, RemoveWhenEmpty) {
  EXPECT_FALSE(session_map_.Remove(kUsername1));

  EXPECT_EQ(session_map_.size(), 0);
  EXPECT_EQ(session_map_.Find(kUsername1), nullptr);
}

TEST_F(UserSessionMapTest, RemoveNonExisting) {
  auto session = std::make_unique<MockUserSession>();
  const UserSession* session_ptr = session.get();
  EXPECT_TRUE(session_map_.Add(kUsername1, std::move(session)));

  EXPECT_FALSE(session_map_.Remove(kUsername2));

  EXPECT_EQ(session_map_.size(), 1);
  EXPECT_EQ(session_map_.Find(kUsername1), session_ptr);
  EXPECT_EQ(session_map_.Find(kUsername2), nullptr);
}

TEST_F(UserSessionMapTest, RemoveTwice) {
  EXPECT_TRUE(
      session_map_.Add(kUsername1, std::make_unique<MockUserSession>()));
  EXPECT_TRUE(session_map_.Remove(kUsername1));

  EXPECT_FALSE(session_map_.Remove(kUsername1));

  EXPECT_EQ(session_map_.size(), 0);
  EXPECT_EQ(session_map_.Find(kUsername1), nullptr);
}

// Use VerifierForwarder to add multiple verifiers before a user session gets
// created and check that they get picked up by the session after it's created.
TEST_F(UserSessionMapTest, AddVerifiersBeforeSession) {
  static constexpr char kLabel1[] = "primary-pass";
  static constexpr char kLabel2[] = "secondary-pass";

  auto [verifier1, ptr1] = MakeTestVerifier(kLabel1);
  auto [verifier2, ptr2] = MakeTestVerifier(kLabel2);
  auto [verifier3, ptr3] = MakeTestVerifier(kLabel1);  // For second user.

  // Create forwarders and give them verifiers.
  auto forwarder1 = std::make_unique<UserSessionMap::VerifierForwarder>(
      kUsername1, &session_map_);
  auto forwarder2 = std::make_unique<UserSessionMap::VerifierForwarder>(
      kUsername2, &session_map_);
  forwarder1->AddVerifier(std::move(verifier1));
  forwarder1->AddVerifier(std::move(verifier2));
  forwarder2->AddVerifier(std::move(verifier3));

  // Confirm that the user sessions don't exist.
  ASSERT_THAT(session_map_.Find(kUsername1), IsNull());
  ASSERT_THAT(session_map_.Find(kUsername2), IsNull());

  // Create the users, they should get the verifiers from the forwarders.
  EXPECT_THAT(session_map_.Add(kUsername1, std::make_unique<MockUserSession>()),
              IsTrue());
  EXPECT_THAT(session_map_.Add(kUsername2, std::make_unique<MockUserSession>()),
              IsTrue());
  auto* user1 = session_map_.Find(kUsername1);
  ASSERT_THAT(user1, Not(IsNull()));
  EXPECT_THAT(user1->GetCredentialVerifiers(),
              UnorderedElementsAre(ptr1, ptr2));
  auto* user2 = session_map_.Find(kUsername2);
  ASSERT_THAT(user2, Not(IsNull()));
  EXPECT_THAT(user2->GetCredentialVerifiers(), UnorderedElementsAre(ptr3));

  // Deleting the forwarders should do nothing.
  forwarder1 = nullptr;
  forwarder2 = nullptr;
  EXPECT_THAT(user1->GetCredentialVerifiers(),
              UnorderedElementsAre(ptr1, ptr2));
  EXPECT_THAT(user2->GetCredentialVerifiers(), UnorderedElementsAre(ptr3));
}

// Use VerifierForwarder to add multiple verifiers after a user session gets
// created and check that they go immediately to the session.
TEST_F(UserSessionMapTest, AddVerifiersAfterSession) {
  static constexpr char kLabel1[] = "primary-pass";
  static constexpr char kLabel2[] = "secondary-pass";

  auto [verifier1, ptr1] = MakeTestVerifier(kLabel1);
  auto [verifier2, ptr2] = MakeTestVerifier(kLabel2);
  auto [verifier3, ptr3] = MakeTestVerifier(kLabel1);  // For second user.

  // Create the users.
  EXPECT_THAT(session_map_.Add(kUsername1, std::make_unique<MockUserSession>()),
              IsTrue());
  EXPECT_THAT(session_map_.Add(kUsername2, std::make_unique<MockUserSession>()),
              IsTrue());
  auto* user1 = session_map_.Find(kUsername1);
  ASSERT_THAT(user1, Not(IsNull()));
  auto* user2 = session_map_.Find(kUsername2);
  ASSERT_THAT(user2, Not(IsNull()));

  // Create forwarders and give them verifiers.
  auto forwarder1 = std::make_unique<UserSessionMap::VerifierForwarder>(
      kUsername1, &session_map_);
  auto forwarder2 = std::make_unique<UserSessionMap::VerifierForwarder>(
      kUsername2, &session_map_);
  forwarder1->AddVerifier(std::move(verifier1));
  forwarder1->AddVerifier(std::move(verifier2));
  forwarder2->AddVerifier(std::move(verifier3));

  // The sessions should have the verifiers.
  EXPECT_THAT(user1->GetCredentialVerifiers(),
              UnorderedElementsAre(ptr1, ptr2));
  EXPECT_THAT(user2->GetCredentialVerifiers(), UnorderedElementsAre(ptr3));

  // Deleting the forwarders should do nothing.
  forwarder1 = nullptr;
  forwarder2 = nullptr;
  EXPECT_THAT(user1->GetCredentialVerifiers(),
              UnorderedElementsAre(ptr1, ptr2));
  EXPECT_THAT(user2->GetCredentialVerifiers(), UnorderedElementsAre(ptr3));
}

// Use VerifierForwarder to add multiple verifiers for the same user after the
// session ends. In particular, this test checks that forwarders don't have
// dangling pointers on the session.
TEST_F(UserSessionMapTest, AddVerifiersAfterSessionEndViaCoincidingForwarders) {
  constexpr char kLabel1[] = "primary-pass";
  constexpr char kLabel2[] = "secondary-pass";

  // Arrange: create session, forwarders and then destroy the session.
  EXPECT_THAT(session_map_.Add(kUsername1, std::make_unique<MockUserSession>()),
              IsTrue());
  UserSessionMap::VerifierForwarder forwarder1(kUsername1, &session_map_);
  UserSessionMap::VerifierForwarder forwarder2(kUsername1, &session_map_);
  EXPECT_THAT(session_map_.Remove(kUsername1), IsTrue());

  // Act: add verifiers and then create new session.
  auto [verifier1, ptr1] = MakeTestVerifier(kLabel1);
  forwarder1.AddVerifier(std::move(verifier1));
  auto [verifier2, ptr2] = MakeTestVerifier(kLabel2);
  forwarder2.AddVerifier(std::move(verifier2));
  EXPECT_THAT(session_map_.Add(kUsername1, std::make_unique<MockUserSession>()),
              IsTrue());

  // Assert: the session should have verifiers from both forwarders.
  auto* user = session_map_.Find(kUsername1);
  ASSERT_THAT(user, Not(IsNull()));
  EXPECT_THAT(user->GetCredentialVerifiers(), UnorderedElementsAre(ptr1, ptr2));
}

// Use VerifierForwarder to add verifiers both before and after a session is
// created.
TEST_F(UserSessionMapTest, AddVerifiersBeforeAndAfterSession) {
  static constexpr char kLabel1[] = "primary-pass";
  static constexpr char kLabel2[] = "secondary-pass";

  auto [verifier1, ptr1] = MakeTestVerifier(kLabel1);
  auto [verifier2, ptr2] = MakeTestVerifier(kLabel2);

  // Create a forwarder and give it a verifier.
  auto forwarder = std::make_unique<UserSessionMap::VerifierForwarder>(
      kUsername1, &session_map_);
  forwarder->AddVerifier(std::move(verifier1));

  // Confirm that the user session doesn't exist.
  ASSERT_THAT(session_map_.Find(kUsername1), IsNull());

  // Create the user and add the other verifier. It should end up with both.
  EXPECT_THAT(session_map_.Add(kUsername1, std::make_unique<MockUserSession>()),
              IsTrue());
  auto* user = session_map_.Find(kUsername1);
  ASSERT_THAT(user, Not(IsNull()));
  forwarder->AddVerifier(std::move(verifier2));
  EXPECT_THAT(user->GetCredentialVerifiers(), UnorderedElementsAre(ptr1, ptr2));

  // Deleting the forwarder should do nothing.
  forwarder = nullptr;
  EXPECT_THAT(user->GetCredentialVerifiers(), UnorderedElementsAre(ptr1, ptr2));
}

// Use VerifierForwarder to add verifiers both before and after a session is
// created.
TEST_F(UserSessionMapTest, DetachingVerifiersShouldLoseOldVerifiers) {
  static constexpr char kLabel1[] = "primary-pass";
  static constexpr char kLabel2[] = "secondary-pass";

  auto [verifier1, ptr1] = MakeTestVerifier(kLabel1);
  auto [verifier2, ptr2] = MakeTestVerifier(kLabel2);

  // Create a forwarder and give it a verifier.
  auto forwarder = std::make_unique<UserSessionMap::VerifierForwarder>(
      kUsername1, &session_map_);
  forwarder->AddVerifier(std::move(verifier1));

  // Confirm that the user session doesn't exist.
  ASSERT_THAT(session_map_.Find(kUsername1), IsNull());

  // Create the user. It should have the verifier.
  EXPECT_THAT(session_map_.Add(kUsername1, std::make_unique<MockUserSession>()),
              IsTrue());
  auto* user = session_map_.Find(kUsername1);
  ASSERT_THAT(user, Not(IsNull()));
  EXPECT_THAT(user->GetCredentialVerifiers(), UnorderedElementsAre(ptr1));

  // Delete the user, which should detach the verifier.
  EXPECT_THAT(session_map_.Remove(kUsername1), IsTrue());
  ASSERT_THAT(session_map_.Find(kUsername1), IsNull());

  // Add another verifier to the forwarder, and then re-create the user. It
  // should have the new verifier but not the old one which should be gone.
  forwarder->AddVerifier(std::move(verifier2));
  EXPECT_THAT(session_map_.Add(kUsername1, std::make_unique<MockUserSession>()),
              IsTrue());
  user = session_map_.Find(kUsername1);
  ASSERT_THAT(user, Not(IsNull()));
  EXPECT_THAT(user->GetCredentialVerifiers(), UnorderedElementsAre(ptr2));

  // Deleting the forwarder should do nothing.
  forwarder = nullptr;
  EXPECT_THAT(user->GetCredentialVerifiers(), UnorderedElementsAre(ptr2));
}

// Check that deleting a forwarder drops any un-forwarded verifiers.
TEST_F(UserSessionMapTest, DeletedForwardersDropsUnforwardedVerifiers) {
  static constexpr char kLabel1[] = "primary-pass";
  static constexpr char kLabel2[] = "secondary-pass";

  auto [verifier1, ptr1] = MakeTestVerifier(kLabel1);
  auto [verifier2, ptr2] = MakeTestVerifier(kLabel2);

  // Create a forwarder and give it a verifier.
  auto forwarder = std::make_unique<UserSessionMap::VerifierForwarder>(
      kUsername1, &session_map_);
  forwarder->AddVerifier(std::move(verifier1));

  // Destroy the forwarder and replace it with a fresh one.
  forwarder = nullptr;
  forwarder = std::make_unique<UserSessionMap::VerifierForwarder>(
      kUsername1, &session_map_);
  forwarder->AddVerifier(std::move(verifier2));

  // Confirm that the user session doesn't exist.
  ASSERT_THAT(session_map_.Find(kUsername1), IsNull());

  // Create the user, it should get just the verifier from the second forwarder.
  EXPECT_THAT(session_map_.Add(kUsername1, std::make_unique<MockUserSession>()),
              IsTrue());
  auto* user = session_map_.Find(kUsername1);
  ASSERT_THAT(user, Not(IsNull()));
  EXPECT_THAT(user->GetCredentialVerifiers(), UnorderedElementsAre(ptr2));

  // Deleting the forwarder should do nothing.
  forwarder = nullptr;
  EXPECT_THAT(user->GetCredentialVerifiers(), UnorderedElementsAre(ptr2));
}

}  // namespace
}  // namespace cryptohome
