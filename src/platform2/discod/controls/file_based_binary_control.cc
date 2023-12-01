// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "discod/controls/file_based_binary_control.h"

#include <string>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>

#include "discod/controls/binary_control.h"
#include "discod/utils/libhwsec_status_import.h"

namespace discod {

FileBasedBinaryControl::FileBasedBinaryControl(
    const base::FilePath& control_node)
    : control_node_(control_node) {}

Status FileBasedBinaryControl::Toggle(BinaryControl::State state) {
  if (!base::WriteFile(control_node_,
                       state == BinaryControl::State::kOn ? "1" : "0")) {
    return MakeStatus(
        "Couldn't toggle FileBasedBinaryControl: node=" +
        control_node_.value() +
        " error=" + base::File::ErrorToString(base::File::GetLastFileError()));
  }
  return OkStatus();
}

StatusOr<BinaryControl::State> FileBasedBinaryControl::Current() const {
  std::string value;
  if (!base::ReadFileToString(control_node_, &value)) {
    return MakeStatus(
        "Couldn't read current FileBasedBinaryControl: node=" +
        control_node_.value() +
        " error=" + base::File::ErrorToString(base::File::GetLastFileError()));
  }

  if (value == "1") {
    return BinaryControl::State::kOn;
  } else if (value == "0") {
    return BinaryControl::State::kOff;
  }

  return MakeStatus("Unrecognized current FileBasedBinaryControl: node=" +
                    control_node_.value() + " value=" + value);
}

}  // namespace discod
