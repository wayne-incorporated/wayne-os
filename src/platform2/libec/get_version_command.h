// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_GET_VERSION_COMMAND_H_
#define LIBEC_GET_VERSION_COMMAND_H_

#include <array>
#include <string>
#include <vector>

#include <brillo/brillo_export.h>
#include "libec/ec_command.h"

namespace ec {

class BRILLO_EXPORT GetVersionCommand
    : public EcCommand<EmptyParam, struct ec_response_get_version> {
 public:
  GetVersionCommand() : EcCommand(EC_CMD_GET_VERSION) {}
  ~GetVersionCommand() override = default;

  bool Run(int fd) override;

  std::string RWVersion() const;
  std::string ROVersion() const;
  ec_image Image() const;

 protected:
  virtual bool EcCommandRun(int fd);

 private:
  std::string rw_version_;
  std::string ro_version_;
  ec_image image_ = EC_IMAGE_UNKNOWN;
};

static_assert(!std::is_copy_constructible<GetVersionCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<GetVersionCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_GET_VERSION_COMMAND_H_
