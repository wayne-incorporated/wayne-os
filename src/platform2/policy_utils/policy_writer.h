// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POLICY_UTILS_POLICY_WRITER_H_
#define POLICY_UTILS_POLICY_WRITER_H_

#include <string>

#include <base/files/file_path.h>
#include <brillo/brillo_export.h>

namespace policy_utils {

// LibMgmt interface for writing local policy overrides.
// Calling Set<PolicyName>(value) generates a JSON file with name
// /etc/opt/chrome/policies/recommended/policy_name.json with content
// "{ 'PolicyName': value }". Chrome will automatically load the policy,
// effectively overriding the policy on the device.
class BRILLO_EXPORT PolicyWriter {
 public:
  // Creates a PolicyWriter that writes JSON policy-override files in the
  // given directory. Leave |dest_dir_path| empty to use the recommended
  // directory (/etc/opt/chrome/policies/recommended/). Using a directory other
  // than recommended is only useful for testing.
  explicit PolicyWriter(const std::string& dest_dir_path);
  PolicyWriter(const PolicyWriter&) = delete;
  PolicyWriter& operator=(const PolicyWriter&) = delete;

  ~PolicyWriter();

  // Sets policy DeviceAllowBluetooth to value |is_allowed|. Returns whether
  // successful.
  bool SetDeviceAllowBluetooth(bool is_allowed) const;
  bool SetShowHomeButton(bool show) const;
  bool SetBookmarkBarEnabled(bool is_enabled) const;

  // Clears local policy DeviceAllowBluetooth by deleting its local JSON file
  // override if it exists. Returns whether successful.
  bool ClearDeviceAllowBluetooth() const;
  bool ClearShowHomeButton() const;
  bool ClearBookmarkBarEnabled() const;

 private:
  // The path to the directory into which JSON policy files should be written.
  base::FilePath dest_dir_path_;
};

}  // namespace policy_utils

#endif  // POLICY_UTILS_POLICY_WRITER_H_
