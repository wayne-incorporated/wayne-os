// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_PLATFORM_PLATFORM_IMPL_H_
#define LIBHWSEC_PLATFORM_PLATFORM_IMPL_H_

#include <string>

#include <base/files/file_path.h>

#include "libhwsec/platform/platform.h"

namespace hwsec {

class PlatformImpl : public Platform {
 public:
  PlatformImpl() = default;
  ~PlatformImpl() override = default;

  bool ReadFileToString(const base::FilePath& path,
                        std::string* contents) override;
};

}  // namespace hwsec

#endif  // LIBHWSEC_PLATFORM_PLATFORM_IMPL_H_
