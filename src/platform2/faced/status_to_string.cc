// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/status_to_string.h"

#include <string>

#include <base/strings/strcat.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_piece.h>

#include "faced/mojom/faceauth.mojom.h"

namespace faced {

using ::chromeos::faceauth::mojom::FaceOperationStatus;
using ::chromeos::faceauth::mojom::SessionCreationError;
using ::chromeos::faceauth::mojom::SessionError;

std::string SessionCreationErrorString(SessionCreationError error) {
  switch (error) {
    case SessionCreationError::UNKNOWN:
      return "Unknown";
    case SessionCreationError::ALREADY_EXISTS:
      return "Already exists";
    default:
      return base::StrCat({"SessionCreationError code: ",
                           base::NumberToString(static_cast<int>(error))});
  }
}

std::string FaceOperationStatusString(FaceOperationStatus status) {
  switch (status) {
    case FaceOperationStatus::OK:
      return "Face detected";
    case FaceOperationStatus::NO_FACE:
      return "No face detected";
    default:
      return base::StrCat({"FaceOperationStatus code: ",
                           base::NumberToString(static_cast<int>(status))});
  }
}

std::string SessionErrorString(SessionError error) {
  switch (error) {
    case SessionError::UNKNOWN:
      return "Unknown";
    case SessionError::NO_ENROLLMENT:
      return "No enrollment";
    default:
      return base::StrCat({"SessionError code: ",
                           base::NumberToString(static_cast<int>(error))});
  }
}

}  // namespace faced
