// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROMEOS_CONFIG_LIBCROS_CONFIG_FAKE_CROS_CONFIG_H_
#define CHROMEOS_CONFIG_LIBCROS_CONFIG_FAKE_CROS_CONFIG_H_

#include <map>
#include <string>
#include <utility>

#include <brillo/brillo_export.h>
#include "chromeos-config/libcros_config/cros_config_interface.h"

namespace brillo {

// Provides a simple Fake to use for testing modules that use CrosConfig.
// It allows configuration responses to be set up in the test for use in the
// module.
class BRILLO_EXPORT FakeCrosConfig : public CrosConfigInterface {
 public:
  FakeCrosConfig();
  FakeCrosConfig(const FakeCrosConfig&) = delete;
  FakeCrosConfig& operator=(const FakeCrosConfig&) = delete;

  ~FakeCrosConfig() override;

  // Sets up string to return for a future call to GetString().
  // @path: Path to property (e.g. "/")
  // @property: Name of property to set up
  // @val: The string to return when this property is looked up.
  void SetString(const std::string& path,
                 const std::string& property,
                 const std::string& val);

  // CrosConfigInterface:
  bool GetString(const std::string& path,
                 const std::string& property,
                 std::string* val_out) override;

 private:
  using PathProp = std::pair<std::string, std::string>;

  // This stores the string values, keyed by a pair consisting of the path
  // and the property.
  std::map<PathProp, std::string> values_;
};

}  // namespace brillo

#endif  // CHROMEOS_CONFIG_LIBCROS_CONFIG_FAKE_CROS_CONFIG_H_
