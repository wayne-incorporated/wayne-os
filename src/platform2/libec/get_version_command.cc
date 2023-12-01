// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include "libec/get_version_command.h"

namespace ec {

std::string GetVersionCommand::RWVersion() const {
  return rw_version_;
}

std::string GetVersionCommand::ROVersion() const {
  return ro_version_;
}

ec_image GetVersionCommand::Image() const {
  return image_;
}

bool GetVersionCommand::Run(int fd) {
  bool ret = EcCommandRun(fd);
  if (!ret) {
    return false;
  }

  // The buffers should already be NUL terminated, but be safe.
  Resp()->version_string_ro[sizeof(Resp()->version_string_ro) - 1] = '\0';
  Resp()->version_string_rw[sizeof(Resp()->version_string_rw) - 1] = '\0';

  ro_version_ = std::string(Resp()->version_string_ro);
  rw_version_ = std::string(Resp()->version_string_rw);
  image_ = static_cast<ec_image>(Resp()->current_image);

  return true;
}

bool GetVersionCommand::EcCommandRun(int fd) {
  return EcCommand::Run(fd);
}

}  // namespace ec
