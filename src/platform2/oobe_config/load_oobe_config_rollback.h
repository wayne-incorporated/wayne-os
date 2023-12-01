// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OOBE_CONFIG_LOAD_OOBE_CONFIG_ROLLBACK_H_
#define OOBE_CONFIG_LOAD_OOBE_CONFIG_ROLLBACK_H_

#include "oobe_config/filesystem/file_handler.h"
#include "oobe_config/load_oobe_config_interface.h"

#include <string>

#include <base/files/file_path.h>

#include "oobe_config/metrics/metrics_uma.h"

namespace oobe_config {

class OobeConfig;
class RollbackData;

// An object of this class has the responsibility of loading the oobe config
// file after rollback.
class LoadOobeConfigRollback : public LoadOobeConfigInterface {
 public:
  explicit LoadOobeConfigRollback(OobeConfig* oobe_config,
                                  FileHandler file_handler = FileHandler());
  LoadOobeConfigRollback(const LoadOobeConfigRollback&) = delete;
  LoadOobeConfigRollback& operator=(const LoadOobeConfigRollback&) = delete;

  ~LoadOobeConfigRollback() = default;

  bool GetOobeConfigJson(std::string* config,
                         std::string* enrollment_domain) override;

 private:
  // Assembles a JSON config for Chrome based on rollback_data. Returns true if
  // |config| is successfully populated during stage 3 of rollback. Returns
  // false to indicate that either rollback was not attempted or there was a
  // failure. During stage 1 of rollback, the process exits before returning.
  bool AssembleConfig(const RollbackData& rollback_data, std::string* config);

  FileHandler file_handler_;
  OobeConfig* oobe_config_;
  MetricsUMA metrics_uma_;  // For UMA metrics logging.
};

}  // namespace oobe_config

#endif  // OOBE_CONFIG_LOAD_OOBE_CONFIG_ROLLBACK_H_
