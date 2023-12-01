// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_CGPT_UTIL_H_
#define MINIOS_CGPT_UTIL_H_

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include <base/files/file_path.h>

#include "minios/cgpt_util_interface.h"
#include "minios/cgpt_wrapper_interface.h"

namespace minios {

class CgptUtil : public CgptUtilInterface {
 public:
  // Construct wrapper with path to the partition table location. Ex:
  // /tmp/test.img or /dev/nvme0n1.
  CgptUtil(const base::FilePath& drive_path,
           std::shared_ptr<CgptWrapperInterface> cgpt);

  CgptUtil(const CgptUtil&) = delete;
  CgptUtil& operator=(const CgptUtil&) = delete;

  ~CgptUtil() override = default;

  // Get partition number from the label property.
  std::optional<int> GetPartitionNumber(
      const std::string& label) const override;
  // Get size of partition from partition number.
  std::optional<uint64_t> GetSize(
      const uint32_t partition_number) const override;

 private:
  base::FilePath drive_path_;
  std::shared_ptr<CgptWrapperInterface> cgpt_;
};

}  // namespace minios

#endif  // MINIOS_CGPT_UTIL_H_
