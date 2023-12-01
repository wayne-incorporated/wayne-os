// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_ENROLLMENT_STORAGE_H_
#define FACED_ENROLLMENT_STORAGE_H_

#include <string>
#include <vector>

#include <absl/status/status.h>
#include <absl/status/statusor.h>
#include <base/files/file_path.h>
#include <base/strings/string_piece.h>

#include "faced/mojom/faceauth.mojom.h"

namespace faced {

inline constexpr char kDaemonStorePath[] = "/run/daemon-store";

// EnrollmentStorage reads and writes enrollments per user to disk to a daemon
// store folder that is shared with the user's cryptohome.
class EnrollmentStorage {
 public:
  // Constructor sets the file path to be /run/daemon-store/faced/<user_id>,
  // which is bound to /home/root/<user_id>/faced.
  explicit EnrollmentStorage(
      const base::FilePath& root_path = base::FilePath(kDaemonStorePath))
      : root_path_(root_path) {}

  // Writes an enrollment for a specified user.
  absl::Status WriteEnrollment(base::StringPiece user_id,
                               base::StringPiece data);

  // Reads an enrollment for a specified user.
  absl::StatusOr<std::string> ReadEnrollment(base::StringPiece user_id);

  // Returns a list of the EnrollmentMetadatas associated with the enrollments
  // that have currently been saved, sorted by username.
  //
  // Instead of storing state of what enrollments have been saved,
  // ListEnrollments checks for the existence of saved enrollment files.
  std::vector<chromeos::faceauth::mojom::EnrollmentMetadataPtr>
  ListEnrollments();

  // Delete the enrollment of a given user.
  //
  // If an enrollment doesn't exist, returns failure.
  absl::Status RemoveEnrollment(base::StringPiece user_id);

  // Delete all enrollments.
  //
  // ClearEnrollments will make a best effort to delete all enrollments even if
  // any one of its operations fails. In the event of failing to delete an
  // enrollment, ClearEnrollments will report an error.
  absl::Status ClearEnrollments();

  // Return true if the given user has been enrolled.
  bool IsUserEnrolled(base::StringPiece user_id);

 private:
  // Returns the filepath to load and save an enrollment given a user_id.
  base::FilePath GetEnrollmentFilePath(base::StringPiece user_id);

  // Returns the filepath where faced user enrollments are saved.
  base::FilePath GetFacedFilePath();

  base::FilePath root_path_;
};

}  // namespace faced

#endif  // FACED_ENROLLMENT_STORAGE_H_
