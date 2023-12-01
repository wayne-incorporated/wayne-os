// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/common/face_status.h"

#include <absl/status/status.h>
#include <base/strings/stringprintf.h>

namespace faced {

using faceauth::eora::FaceStatusCode;

absl::Status ToAbslStatus(const FaceStatusCode& face_status) {
  switch (static_cast<StatusCode>(face_status.status())) {
    case StatusCode::kOk:
      return absl::OkStatus();
    default:
      return absl::UnknownError(base::StringPrintf(
          "FaceStatusCode: %d", static_cast<int>(face_status.status())));
  }
}

}  // namespace faced
