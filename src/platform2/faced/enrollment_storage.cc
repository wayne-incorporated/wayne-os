// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/enrollment_storage.h"

#include <algorithm>
#include <string>

#include <absl/status/status.h>
#include <absl/status/statusor.h>
#include <absl/strings/str_cat.h>
#include <base/files/file.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/important_file_writer.h>
#include <base/strings/strcat.h>
#include <base/strings/string_piece.h>

#include "faced/mojom/faceauth.mojom.h"

namespace faced {
namespace {

// Name of daemon.
constexpr char kFaced[] = "faced";
// Name of enrollment file to read and write from.
constexpr char kEnrollmentFileName[] = "enrollment";

using ::chromeos::faceauth::mojom::EnrollmentMetadata;
using ::chromeos::faceauth::mojom::EnrollmentMetadataPtr;

}  // namespace

absl::Status EnrollmentStorage::WriteEnrollment(base::StringPiece user_id,
                                                base::StringPiece data) {
  base::FilePath save_path = GetEnrollmentFilePath(user_id);

  base::File::Error error;
  if (!CreateDirectoryAndGetError(save_path.DirName(), &error)) {
    return absl::UnavailableError(
        base::StrCat({"Unable to create directory for user: ",
                      base::File::ErrorToString(error)}));
  }

  if (!base::ImportantFileWriter::WriteFileAtomically(save_path, data)) {
    return absl::UnavailableError(
        "Unable to save enrollment to file for user.");
  }

  return absl::OkStatus();
}

absl::StatusOr<std::string> EnrollmentStorage::ReadEnrollment(
    base::StringPiece user_id) {
  base::FilePath enrollment_path = GetEnrollmentFilePath(user_id);

  std::string data;
  if (!base::ReadFileToString(enrollment_path, &data)) {
    return absl::UnavailableError("Unable to read enrollment for user.");
  }

  return data;
}

std::vector<EnrollmentMetadataPtr> EnrollmentStorage::ListEnrollments() {
  std::vector<EnrollmentMetadataPtr> ret;

  base::FilePath faced_path = root_path_.Append(kFaced);
  base::FileEnumerator enum_users(faced_path, /*recursive=*/false,
                                  base::FileEnumerator::DIRECTORIES);
  for (base::FilePath user_path = enum_users.Next(); !user_path.empty();
       user_path = enum_users.Next()) {
    std::string user_id = user_path.BaseName().value();
    base::FilePath user_enrollment_path = GetEnrollmentFilePath(user_id);

    // Check if an enrollment exists for the user.
    if (base::PathExists(user_enrollment_path)) {
      ret.push_back(EnrollmentMetadata::New(user_id));
    }
  }

  // Sort the usernames to ensure the result of this function is deterministic,
  // and not based on the order the filesystem happened to list files in.
  std::sort(ret.begin(), ret.end(),
            [](const EnrollmentMetadataPtr& a, const EnrollmentMetadataPtr& b) {
              // Sort by username.
              return a->hashed_username < b->hashed_username;
            });

  return ret;
}

absl::Status EnrollmentStorage::RemoveEnrollment(base::StringPiece user_id) {
  base::FilePath enrollment_path = GetEnrollmentFilePath(user_id);

  if (!base::PathExists(enrollment_path)) {
    return absl::NotFoundError("No enrollment found for user.");
  }

  if (!base::DeleteFile(enrollment_path)) {
    return absl::InternalError("Unable to remove enrollment.");
  }

  return absl::OkStatus();
}

absl::Status EnrollmentStorage::ClearEnrollments() {
  absl::Status ret = absl::OkStatus();

  for (const EnrollmentMetadataPtr& enrollment : ListEnrollments()) {
    if (!RemoveEnrollment(enrollment->hashed_username).ok()) {
      ret = absl::InternalError("Unable to clear enrollments.");
    }
  }

  return ret;
}

bool EnrollmentStorage::IsUserEnrolled(base::StringPiece user_id) {
  return base::PathExists(GetEnrollmentFilePath((user_id)));
}

base::FilePath EnrollmentStorage::GetEnrollmentFilePath(
    base::StringPiece user_id) {
  return GetFacedFilePath().Append(user_id).Append(kEnrollmentFileName);
}

base::FilePath EnrollmentStorage::GetFacedFilePath() {
  return root_path_.Append(kFaced);
}

}  // namespace faced
