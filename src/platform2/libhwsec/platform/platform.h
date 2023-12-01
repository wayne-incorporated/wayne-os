// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_PLATFORM_PLATFORM_H_
#define LIBHWSEC_PLATFORM_PLATFORM_H_

#include <string>

#include "base/files/file_path.h"

namespace hwsec {

// Platform is an interface for encapsulating other access to the operating
// system, so as to make testing easier.
class Platform {
 public:
  Platform() = default;
  virtual ~Platform() = default;

  // Reads the content of a file to string.
  virtual bool ReadFileToString(const base::FilePath& path,
                                std::string* contents) = 0;
};

}  // namespace hwsec

#endif  // LIBHWSEC_PLATFORM_PLATFORM_H_
