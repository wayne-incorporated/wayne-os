// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FRONTEND_OPTEE_PLUGIN_MOCK_FRONTEND_H_
#define LIBHWSEC_FRONTEND_OPTEE_PLUGIN_MOCK_FRONTEND_H_

#include <optional>
#include <vector>

#include <brillo/secure_blob.h>
#include <gmock/gmock.h>

#include "libhwsec/frontend/mock_frontend.h"
#include "libhwsec/frontend/optee-plugin/frontend.h"

namespace hwsec {

class MockOpteePluginFrontend : public MockFrontend,
                                public OpteePluginFrontend {
 public:
  MockOpteePluginFrontend() = default;
  ~MockOpteePluginFrontend() override = default;

  MOCK_METHOD(StatusOr<brillo::Blob>,
              SendRawCommand,
              (const brillo::Blob& command),
              (const override));
};

}  // namespace hwsec

#endif  // LIBHWSEC_FRONTEND_OPTEE_PLUGIN_MOCK_FRONTEND_H_
