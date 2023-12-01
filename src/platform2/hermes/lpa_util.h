// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_LPA_UTIL_H_
#define HERMES_LPA_UTIL_H_

#include <memory>

#include <brillo/errors/error.h>

namespace hermes {

// Create a brillo Error from an Lpa error code. Return nullptr if no error.
brillo::ErrorPtr LpaErrorToBrillo(const base::Location& location, int error);

}  // namespace hermes

#endif  // HERMES_LPA_UTIL_H_
