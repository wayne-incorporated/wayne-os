// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/platform/fake_platform.h"

#include <base/files/file_util.h>
#include <gmock/gmock.h>

using testing::_;
using testing::Invoke;

namespace hwsec {

FakePlatform::FakePlatform() {
  CHECK(temp_dir_.CreateUniqueTempDir());
  root_ = temp_dir_.GetPath();
  ON_CALL(*this, ReadFileToString(_, _))
      .WillByDefault(Invoke(this, &FakePlatform::ReadFileToStringInternal));
}

bool FakePlatform::ReadFileToStringInternal(const base::FilePath& path,
                                            std::string* contents) {
  base::FilePath actual = root_.Append(path);
  return base::ReadFileToString(actual, contents);
}

}  // namespace hwsec
