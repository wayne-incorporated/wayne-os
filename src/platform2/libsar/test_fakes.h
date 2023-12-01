// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBSAR_TEST_FAKES_H_
#define LIBSAR_TEST_FAKES_H_

#include <map>
#include <string>

#include <base/files/file_path.h>
#include <base/values.h>
#include <brillo/brillo_export.h>
#include <chromeos-config/libcros_config/cros_config_interface.h>

#include "libsar/sar_config_reader.h"

namespace libsar {
namespace fakes {

class BRILLO_EXPORT FakeSarConfigReaderDelegate
    : public SarConfigReader::Delegate {
 public:
  std::optional<std::string> ReadFileToString(const base::FilePath&) override;

  void SetStringToFile(const base::FilePath&, const std::string&);

 private:
  std::map<base::FilePath, std::string> existing_files_with_data_;
};

}  // namespace fakes
}  // namespace libsar

#endif  // LIBSAR_TEST_FAKES_H_
