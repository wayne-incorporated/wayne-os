// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBSAR_SAR_CONFIG_READER_H_
#define LIBSAR_SAR_CONFIG_READER_H_

#include <optional>
#include <string>

#include <base/files/file_path.h>
#include <base/values.h>
#include <brillo/brillo_export.h>
#include <chromeos-config/libcros_config/cros_config_interface.h>

namespace libsar {

class BRILLO_EXPORT SarConfigReader {
 public:
  // CrosConfig Property for system path.
  static constexpr char kSystemPathProperty[] = "system-path";

  class Delegate {
   public:
    virtual ~Delegate() = default;

    virtual std::optional<std::string> ReadFileToString(
        const base::FilePath& fp) = 0;
  };

  SarConfigReader(brillo::CrosConfigInterface* cros_config,
                  std::string devlink,
                  Delegate* delegate);
  ~SarConfigReader();

  bool isCellular() const;
  bool isWifi() const;

  std::optional<base::Value::Dict> GetSarConfigDict() const;

 private:
  brillo::CrosConfigInterface* const cros_config_;
  const std::string devlink_;
  Delegate* delegate_;
};

}  // namespace libsar

#endif  // LIBSAR_SAR_CONFIG_READER_H_
