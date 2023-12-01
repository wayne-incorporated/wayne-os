// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_STATUS_TO_STRING_H_
#define FACED_STATUS_TO_STRING_H_

#include <string>

#include <base/strings/string_piece.h>

#include "faced/mojom/faceauth.mojom.h"

namespace faced {

// Returns human readable strings from the mojo enums.
std::string SessionCreationErrorString(
    chromeos::faceauth::mojom::SessionCreationError error);
std::string FaceOperationStatusString(
    chromeos::faceauth::mojom::FaceOperationStatus status);
std::string SessionErrorString(chromeos::faceauth::mojom::SessionError error);

}  // namespace faced

#endif  // FACED_STATUS_TO_STRING_H_
