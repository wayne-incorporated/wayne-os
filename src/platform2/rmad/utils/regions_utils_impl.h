// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_REGIONS_UTILS_IMPL_H_
#define RMAD_UTILS_REGIONS_UTILS_IMPL_H_

#include "rmad/utils/regions_utils.h"

#include <string>
#include <vector>

#include <base/files/file_path.h>

namespace rmad {

class RegionsUtilsImpl : public RegionsUtils {
 public:
  RegionsUtilsImpl();
  // Used to inject mocked |regions_file_path_| for testing.
  explicit RegionsUtilsImpl(const base::FilePath& regions_file_path);
  ~RegionsUtilsImpl() override = default;

  bool GetRegionList(std::vector<std::string>* region_list) const override;

 private:
  base::FilePath regions_file_path_;
};

}  // namespace rmad

#endif  // RMAD_UTILS_REGIONS_UTILS_IMPL_H_
