// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libsar/test_fakes.h"

namespace libsar {
namespace fakes {

std::optional<std::string> FakeSarConfigReaderDelegate::ReadFileToString(
    const base::FilePath& fp) {
  auto it = existing_files_with_data_.find(fp);
  if (it == existing_files_with_data_.end())
    return std::nullopt;

  return it->second;
}

void FakeSarConfigReaderDelegate::SetStringToFile(const base::FilePath& fp,
                                                  const std::string& data) {
  existing_files_with_data_.emplace(fp, data);
}

}  // namespace fakes
}  // namespace libsar
