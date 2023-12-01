// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DISCOD_CONTROLS_FILE_BASED_BINARY_CONTROL_H_
#define DISCOD_CONTROLS_FILE_BASED_BINARY_CONTROL_H_

#include <base/files/file_path.h>

#include "discod/controls/binary_control.h"
#include "discod/utils/libhwsec_status_import.h"

namespace discod {

class FileBasedBinaryControl : public BinaryControl {
 public:
  explicit FileBasedBinaryControl(const base::FilePath& control_node);
  ~FileBasedBinaryControl() override = default;

  Status Toggle(BinaryControl::State state) override;
  StatusOr<BinaryControl::State> Current() const override;

 private:
  base::FilePath control_node_;
};

}  // namespace discod

#endif  // DISCOD_CONTROLS_FILE_BASED_BINARY_CONTROL_H_
