// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OOBE_CONFIG_LOAD_OOBE_CONFIG_INTERFACE_H_
#define OOBE_CONFIG_LOAD_OOBE_CONFIG_INTERFACE_H_

#include <string>

namespace oobe_config {

class LoadOobeConfigInterface {
 public:
  LoadOobeConfigInterface() = default;
  LoadOobeConfigInterface(const LoadOobeConfigInterface&) = delete;
  LoadOobeConfigInterface& operator=(const LoadOobeConfigInterface&) = delete;

  virtual ~LoadOobeConfigInterface() = default;

  // Populates |config| with the oobe config file in json format. Additionally
  // populates the |enrollment_domain| if exist any. On error it returns false
  // otherwise it returns true.
  virtual bool GetOobeConfigJson(std::string* config,
                                 std::string* enrollment_domain) = 0;
};

}  // namespace oobe_config

#endif  // OOBE_CONFIG_LOAD_OOBE_CONFIG_INTERFACE_H_
