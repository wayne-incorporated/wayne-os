// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_DEV_FEATURES_TOOL_H_
#define DEBUGD_SRC_DEV_FEATURES_TOOL_H_

#include <string>

#include <brillo/errors/error.h>

namespace debugd {

// A collection of functions to enable various development features.
//
// Each feature has two associated functions, one to enable the feature and one
// to query whether it's been enabled or not.
class DevFeaturesTool {
 public:
  DevFeaturesTool() = default;
  DevFeaturesTool(const DevFeaturesTool&) = delete;
  DevFeaturesTool& operator=(const DevFeaturesTool&) = delete;

  ~DevFeaturesTool() = default;

  bool RemoveRootfsVerification(brillo::ErrorPtr* error) const;
  bool EnableBootFromUsb(brillo::ErrorPtr* error) const;
  bool ConfigureSshServer(brillo::ErrorPtr* error) const;
  bool SetUserPassword(const std::string& username,
                       const std::string& password,
                       brillo::ErrorPtr* error) const;
  bool EnableChromeRemoteDebugging(brillo::ErrorPtr* error) const;
  bool EnableChromeDevFeatures(const std::string& root_password,
                               brillo::ErrorPtr* error) const;

  bool QueryDevFeatures(int32_t* flags, brillo::ErrorPtr* error) const;
};

}  // namespace debugd

#endif  // DEBUGD_SRC_DEV_FEATURES_TOOL_H_
