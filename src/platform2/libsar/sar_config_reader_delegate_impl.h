// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBSAR_SAR_CONFIG_READER_DELEGATE_IMPL_H_
#define LIBSAR_SAR_CONFIG_READER_DELEGATE_IMPL_H_

#include "libsar/sar_config_reader.h"

#include <string>

#include <brillo/brillo_export.h>

namespace libsar {

class BRILLO_EXPORT SarConfigReaderDelegateImpl
    : public SarConfigReader::Delegate {
 public:
  std::optional<std::string> ReadFileToString(const base::FilePath&) override;
};

}  // namespace libsar

#endif  // LIBSAR_SAR_CONFIG_READER_DELEGATE_IMPL_H_
