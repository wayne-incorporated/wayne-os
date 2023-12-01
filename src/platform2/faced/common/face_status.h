// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_COMMON_FACE_STATUS_H_
#define FACED_COMMON_FACE_STATUS_H_

#include <absl/status/status.h>

#include "faced/proto/face_service.pb.h"

namespace faced {

// Status codes for FaceService gRPC responses
enum class StatusCode {
  kOk = 0,
  kGenericError = 1,
};

// Convert eora::FaceStatusCode protocol buffer to an absl status
absl::Status ToAbslStatus(const faceauth::eora::FaceStatusCode& face_status);

}  // namespace faced

#endif  // FACED_COMMON_FACE_STATUS_H_
