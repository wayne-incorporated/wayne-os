// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FRONTEND_OPTEE_PLUGIN_FRONTEND_H_
#define LIBHWSEC_FRONTEND_OPTEE_PLUGIN_FRONTEND_H_

#include <optional>
#include <vector>

#include <brillo/secure_blob.h>

#include "libhwsec/frontend/frontend.h"
#include "libhwsec/status.h"

namespace hwsec {

class OpteePluginFrontend : public Frontend {
 public:
  ~OpteePluginFrontend() override = default;

  // Send the raw command.
  virtual StatusOr<brillo::Blob> SendRawCommand(
      const brillo::Blob& command) const = 0;
};

}  // namespace hwsec

#endif  // LIBHWSEC_FRONTEND_OPTEE_PLUGIN_FRONTEND_H_
