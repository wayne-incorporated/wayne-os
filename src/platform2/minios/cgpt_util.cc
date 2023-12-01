// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "minios/cgpt_util.h"

#include <cstdint>
#include <optional>
#include <utility>

#include <base/logging.h>
#include <vboot/cgpt_params.h>

namespace minios {

CgptUtil::CgptUtil(const base::FilePath& drive_path,
                   std::shared_ptr<CgptWrapperInterface> cgpt)
    : drive_path_(drive_path), cgpt_(cgpt) {}

std::optional<int> CgptUtil::GetPartitionNumber(
    const std::string& label) const {
  CgptFindParams params = {.drive_name = drive_path_.value().c_str(),
                           .set_label = 1,
                           .label = label.c_str()};
  cgpt_->CgptFind(&params);
  if (params.hits != 1) {
    LOG(ERROR) << "Could not find partition number for partition " << label;
    return std::nullopt;
  }
  return params.match_partnum;
}

std::optional<uint64_t> CgptUtil::GetSize(
    const uint32_t partition_number) const {
  CgptAddParams params = {.drive_name = drive_path_.value().c_str(),
                          .partition = partition_number};
  if (cgpt_->CgptGetPartitionDetails(&params) == CGPT_OK) {
    return params.size;
  }
  LOG(ERROR) << "Could not get partition detail for partition: "
             << partition_number;
  return std::nullopt;
}

}  // namespace minios
