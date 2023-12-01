// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/functions/vpd_cached.h"

#include <utility>
#include <vector>

#include "runtime_probe/utils/file_utils.h"
#include "runtime_probe/utils/value_utils.h"

namespace runtime_probe {

namespace {
constexpr char kSysfsVPDCached[] = "/sys/firmware/vpd/ro/";
// sku_number is defined in public partner documentation:
// https://www.google.com/chromeos/partner/fe/docs/factory/vpd.html#field-sku_number
// sku_number is allowed to be exposed as stated in b/130322365#c28
const std::vector<std::string> kAllowedOptionalKeys{"sku_number"};
const auto kKeyPrefix = "vpd_";
};  // namespace

VPDCached::DataType VPDCached::EvalImpl() const {
  const std::vector<std::string> require_keys{vpd_name_};
  auto dict_value = MapFilesToDict(base::FilePath(kSysfsVPDCached),
                                   require_keys, kAllowedOptionalKeys);
  if (!dict_value)
    return {};
  PrependToDVKey(&*dict_value, kKeyPrefix);

  VPDCached::DataType result{};
  result.Append(std::move(*dict_value));
  return result;
}

}  // namespace runtime_probe
