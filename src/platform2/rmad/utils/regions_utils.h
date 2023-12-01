// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_REGIONS_UTILS_H_
#define RMAD_UTILS_REGIONS_UTILS_H_

#include <string>
#include <vector>

namespace rmad {

class RegionsUtils {
 public:
  RegionsUtils() = default;
  virtual ~RegionsUtils() = default;

  // Get all the valid regions of the device, and then store them in the
  // |region_list|. |region_list| is not changed if we fail to get the regions.
  // Return true if successfully get regions, false if fail.
  virtual bool GetRegionList(std::vector<std::string>* region_list) const = 0;
};

}  // namespace rmad

#endif  // RMAD_UTILS_REGIONS_UTILS_H_
