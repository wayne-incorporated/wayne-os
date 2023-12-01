// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include "libec/get_chip_info_command.h"

namespace ec {

GetChipInfoCommand::GetChipInfoCommand() : EcCommand(EC_CMD_GET_CHIP_INFO) {}

bool GetChipInfoCommand::Run(int fd) {
  bool ret = EcCommandRun(fd);
  if (!ret) {
    return false;
  }

  // The buffers should already be NUL terminated, but be safe.
  Resp()->name[sizeof(Resp()->name) - 1] = '\0';
  Resp()->revision[sizeof(Resp()->revision) - 1] = '\0';
  Resp()->vendor[sizeof(Resp()->vendor) - 1] = '\0';

  name_ = std::string(Resp()->name);
  revision_ = std::string(Resp()->revision);
  vendor_ = std::string(Resp()->vendor);

  return true;
}

bool GetChipInfoCommand::EcCommandRun(int fd) {
  return EcCommand::Run(fd);
}

std::string GetChipInfoCommand::name() const {
  return name_;
}

std::string GetChipInfoCommand::revision() const {
  return revision_;
}

std::string GetChipInfoCommand::vendor() const {
  return vendor_;
}

}  // namespace ec
