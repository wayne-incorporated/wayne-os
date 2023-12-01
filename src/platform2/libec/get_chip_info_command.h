// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_GET_CHIP_INFO_COMMAND_H_
#define LIBEC_GET_CHIP_INFO_COMMAND_H_

#include <string>

#include <brillo/brillo_export.h>
#include "libec/ec_command.h"

namespace ec {

class BRILLO_EXPORT GetChipInfoCommand
    : public EcCommand<EmptyParam, struct ec_response_get_chip_info> {
 public:
  GetChipInfoCommand();
  ~GetChipInfoCommand() override = default;

  bool Run(int fd) override;

  std::string name() const;
  std::string revision() const;
  std::string vendor() const;

 protected:
  virtual bool EcCommandRun(int fd);

 private:
  std::string name_;
  std::string revision_;
  std::string vendor_;
};

static_assert(!std::is_copy_constructible<GetChipInfoCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<GetChipInfoCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_GET_CHIP_INFO_COMMAND_H_
