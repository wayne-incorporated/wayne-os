// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Library to provide access to the Chrome OS model configuration

#ifndef CHROMEOS_CONFIG_LIBCROS_CONFIG_CROS_CONFIG_H_
#define CHROMEOS_CONFIG_LIBCROS_CONFIG_CROS_CONFIG_H_

#include <memory>
#include <string>

#include <brillo/brillo_export.h>
#include "chromeos-config/libcros_config/cros_config_interface.h"

namespace brillo {

class BRILLO_EXPORT CrosConfig : public CrosConfigInterface {
 public:
  CrosConfig();
  CrosConfig(const CrosConfig&) = delete;
  CrosConfig& operator=(const CrosConfig&) = delete;

  ~CrosConfig() override;

  // CrosConfigInterface:
  bool GetString(const std::string& path,
                 const std::string& property,
                 std::string* val_out) override;
};

}  // namespace brillo

#endif  // CHROMEOS_CONFIG_LIBCROS_CONFIG_CROS_CONFIG_H_
