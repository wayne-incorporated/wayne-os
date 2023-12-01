// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/utils/regions_utils_impl.h"

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include <base/json/json_file_value_serializer.h>
#include <base/logging.h>
#include <base/values.h>

namespace {

const base::FilePath kCrosRegionsDatabaseDefaultPath(
    "/usr/share/misc/cros-regions.json");
constexpr char kConfirmedRegionKey[] = "confirmed";

}  // namespace

namespace rmad {

RegionsUtilsImpl::RegionsUtilsImpl() {
  regions_file_path_ = kCrosRegionsDatabaseDefaultPath;
}

RegionsUtilsImpl::RegionsUtilsImpl(const base::FilePath& regions_file_path)
    : regions_file_path_(regions_file_path) {}

bool RegionsUtilsImpl::GetRegionList(
    std::vector<std::string>* region_list) const {
  CHECK(region_list);

  JSONFileValueDeserializer deserializer(regions_file_path_);
  int error_code = 0;
  std::string error_msg;
  std::unique_ptr<base::Value> cros_regions =
      deserializer.Deserialize(&error_code, &error_msg);

  if (!cros_regions) {
    LOG(ERROR) << error_msg;
    return false;
  }

  if (!cros_regions->is_dict()) {
    LOG(ERROR) << "Failed to parse the regions file";
    return false;
  }

  region_list->clear();
  for (const auto& [key, value] : cros_regions->GetDict()) {
    if (!value.is_dict()) {
      LOG(WARNING) << "Failed to parse region value as a dictionary";
      continue;
    }

    auto confirmed = value.GetDict().FindBool(kConfirmedRegionKey);
    if (confirmed.has_value() && confirmed.value()) {
      region_list->push_back(key);
    }
  }

  sort(region_list->begin(), region_list->end());

  return true;
}

}  // namespace rmad
