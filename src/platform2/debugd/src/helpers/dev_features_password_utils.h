// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_HELPERS_DEV_FEATURES_PASSWORD_UTILS_H_
#define DEBUGD_SRC_HELPERS_DEV_FEATURES_PASSWORD_UTILS_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>

namespace debugd {

// Class to provide functionality to set and check user passwords.
//
// Functions are gathered into this class in order to provide a testable
// interface.
class DevFeaturesPasswordUtils {
 public:
  DevFeaturesPasswordUtils() = default;
  DevFeaturesPasswordUtils(const DevFeaturesPasswordUtils&) = delete;
  DevFeaturesPasswordUtils& operator=(const DevFeaturesPasswordUtils&) = delete;

  virtual ~DevFeaturesPasswordUtils() = default;

  // Checks if |username| is valid. This may be slightly different than the
  // actual allowed set of usernames, but it will work for our primary use cases
  // of chronos and root.
  bool IsUsernameValid(const std::string& username);

  // Checks if |username| has a valid password in |password_file|. Valid
  // passwords are defined as any non-empty hash that doesn't start with any
  // of '!', '*', or ':'.
  bool IsPasswordSet(const std::string& username,
                     const base::FilePath& password_file);

  // Sets |password| for |username| in |password_file|.
  bool SetPassword(const std::string& username,
                   const std::string& password,
                   const base::FilePath& password_file);

 private:
  // Hash a raw password. Virtual so that we can mock it for testing. Returns
  // false and prints to stderr if hashing failed.
  virtual bool HashPassword(const std::string& password,
                            std::string* hashed_password);

  // Search through |entries| to find the one corresponding to |username|, and
  // replace the password with |hashed_password|. If |username| is not found,
  // a new entry will be added to |entries|.
  bool SetPasswordInEntries(const std::string& username,
                            const std::string& hashed_password,
                            std::vector<std::string>* entries);
};

}  // namespace debugd

#endif  // DEBUGD_SRC_HELPERS_DEV_FEATURES_PASSWORD_UTILS_H_
