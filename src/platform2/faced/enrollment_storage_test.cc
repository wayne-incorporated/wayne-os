// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/enrollment_storage.h"

#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

#include "faced/mojom/faceauth.mojom.h"
#include "faced/testing/status.h"

namespace faced {
namespace {

using ::chromeos::faceauth::mojom::EnrollmentMetadataPtr;
using ::testing::ElementsAre;

constexpr char kUserId1[] = "0000000000000000000000000000000000000001";
constexpr char kData1[] = "Hello, world1!";
constexpr char kUserId2[] = "0000000000000000000000000000000000000002";
constexpr char kData2[] = "Hello, world2!";

// Helper function to extract a vector of userids from a vector of
// EnrollmentMetadataPtrs.
std::vector<std::string> ExtractUserIds(
    const std::vector<EnrollmentMetadataPtr>& enrollments) {
  std::vector<std::string> ret;

  for (const EnrollmentMetadataPtr& enrollment : enrollments) {
    ret.push_back(enrollment->hashed_username);
  }

  return ret;
}

TEST(EnrollmentStorage, SavesAndReadsEnrollmentsCorrectly) {
  // Create a temp directory for saving files
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  EnrollmentStorage storage(temp_dir.GetPath());

  // Enroll a user and check that it is read correctly.
  FACE_ASSERT_OK(storage.WriteEnrollment(kUserId1, kData1));
  FACE_ASSERT_OK_AND_ASSIGN(std::string data1,
                            storage.ReadEnrollment(kUserId1));
  EXPECT_EQ(data1, kData1);
}

TEST(EnrollmentStorage, SavesAndOverwritesEnrollmentsCorrectly) {
  // Create a temp directory for saving files
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  EnrollmentStorage storage(temp_dir.GetPath());

  // Enroll a user, overwrite the saved enrollment and check that it is read
  // correctly.
  FACE_ASSERT_OK(storage.WriteEnrollment(kUserId1, kData1));
  FACE_ASSERT_OK(storage.WriteEnrollment(kUserId1, kData2));
  FACE_ASSERT_OK_AND_ASSIGN(std::string data1,
                            storage.ReadEnrollment(kUserId1));
  EXPECT_EQ(data1, kData2);
}

TEST(EnrollmentStorage, SavesAndReadsTwoEnrollmentsCorrectly) {
  // Create a temp directory for saving files
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  EnrollmentStorage storage(temp_dir.GetPath());

  // Enroll two users and check that their enrollments can be read correctly.
  FACE_ASSERT_OK(storage.WriteEnrollment(kUserId1, kData1));
  FACE_ASSERT_OK(storage.WriteEnrollment(kUserId2, kData2));

  FACE_ASSERT_OK_AND_ASSIGN(std::string data1,
                            storage.ReadEnrollment(kUserId1));
  EXPECT_EQ(data1, kData1);
  FACE_ASSERT_OK_AND_ASSIGN(std::string data2,
                            storage.ReadEnrollment(kUserId2));
  EXPECT_EQ(data2, kData2);
}

TEST(EnrollmentStorage, IsUserEnrolledAndListEnrollmentsWhenNoUsersEnrolled) {
  // Create a temp directory for saving files
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  EnrollmentStorage storage(temp_dir.GetPath());

  // Check that no users are enrolled.
  EXPECT_FALSE(storage.IsUserEnrolled(kUserId1));
  EXPECT_EQ(storage.ListEnrollments().size(), 0);
}

TEST(EnrollmentStorage, IsUserEnrolledAndListEnrollmentsForEnrolledUsers) {
  // Create a temp directory for saving files
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  EnrollmentStorage storage(temp_dir.GetPath());

  // Enroll a user and check that IsUserEnrolled and ListEnrollments produces
  // the correct outputs.
  FACE_ASSERT_OK(storage.WriteEnrollment(kUserId1, kData1));
  EXPECT_TRUE(storage.IsUserEnrolled(kUserId1));
  EXPECT_THAT(ExtractUserIds(storage.ListEnrollments()), ElementsAre(kUserId1));

  // Enroll a second user and check that IsUserEnrolled produces the correct
  // output and ListEnrollments is updated.
  FACE_ASSERT_OK(storage.WriteEnrollment(kUserId2, kData2));
  EXPECT_TRUE(storage.IsUserEnrolled(kUserId2));
  EXPECT_THAT(ExtractUserIds(storage.ListEnrollments()),
              ElementsAre(kUserId1, kUserId2));
}

TEST(EnrollmentStorage, RemoveEnrollmentFailure) {
  // Create a temp directory for saving files
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  EnrollmentStorage storage(temp_dir.GetPath());

  // Remove an enrollment that doesn't exist.
  EXPECT_FALSE(storage.RemoveEnrollment(kUserId1).ok());
}

TEST(EnrollmentStorage, RemoveEnrollmentSuccess) {
  // Create a temp directory for saving files
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  EnrollmentStorage storage(temp_dir.GetPath());

  FACE_ASSERT_OK(storage.WriteEnrollment(kUserId1, kData1));
  FACE_ASSERT_OK(storage.RemoveEnrollment(kUserId1));
  EXPECT_EQ(storage.ListEnrollments().size(), 0);
  EXPECT_FALSE(storage.IsUserEnrolled(kUserId1));
}

TEST(EnrollmentStorage, ClearEnrollmentsWhenAlreadyClear) {
  // Create a temp directory for saving files
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  EnrollmentStorage storage(temp_dir.GetPath());

  // Clear all enrollments when none exist.
  FACE_EXPECT_OK(storage.ClearEnrollments());
}

TEST(EnrollmentStorage, ClearEnrollments) {
  // Create a temp directory for saving files
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  EnrollmentStorage storage(temp_dir.GetPath());

  // Write two enrollments.
  FACE_EXPECT_OK(storage.WriteEnrollment(kUserId1, kData1));
  FACE_EXPECT_OK(storage.WriteEnrollment(kUserId2, kData2));

  // Ensure both exist.
  EXPECT_THAT(ExtractUserIds(storage.ListEnrollments()),
              ElementsAre(kUserId1, kUserId2));

  // Clear all enrollments.
  FACE_EXPECT_OK(storage.ClearEnrollments());

  // Ensure they have both been removed.
  EXPECT_EQ(storage.ListEnrollments().size(), 0);
}

}  // namespace
}  // namespace faced
