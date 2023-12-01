// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_PLATFORM_FAKE_PLATFORM_H_
#define LIBHWSEC_PLATFORM_FAKE_PLATFORM_H_

#include <optional>
#include <string>

#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>

#include "libhwsec/hwsec_export.h"
#include "libhwsec/platform/mock_platform.h"

namespace hwsec {

class HWSEC_EXPORT FakePlatform : public MockPlatform {
 public:
  FakePlatform();
  ~FakePlatform() override = default;

  bool ReadFileToStringInternal(const base::FilePath& path,
                                std::string* contents);

  base::FilePath& get_root() { return root_; }

 private:
  // The root filesystem path for the fake platform.
  base::FilePath root_;

  // The temp directory in use.
  base::ScopedTempDir temp_dir_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_PLATFORM_FAKE_PLATFORM_H_
