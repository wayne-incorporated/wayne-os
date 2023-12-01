// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libsar/sar_config_reader_delegate_impl.h"

#include <base/files/file_util.h>

namespace libsar {

std::optional<std::string> SarConfigReaderDelegateImpl::ReadFileToString(
    const base::FilePath& fp) {
  std::string data;
  if (!base::ReadFileToString(fp, &data))
    return std::nullopt;

  return data;
}

}  // namespace libsar
