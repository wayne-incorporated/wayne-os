// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_MOCK_INSTALL_ATTRIBUTES_READER_H_
#define LOGIN_MANAGER_MOCK_INSTALL_ATTRIBUTES_READER_H_

#include <install_attributes/libinstallattributes.h>

#include <map>
#include <string>

// TODO(tnagel): Move to libbrillo/install_attributes.
class MockInstallAttributesReader : public InstallAttributesReader {
 public:
  // Unlocked and empty install attributes.
  MockInstallAttributesReader() {}

  // Locked install attributes containing |attributes|.
  explicit MockInstallAttributesReader(
      const std::map<std::string, std::string>& attributes) {
    SetAttributes(attributes);
  }

  void SetAttributes(const std::map<std::string, std::string>& attributes) {
    attributes_ = attributes;
    initialized_ = true;
  }

  void SetLocked(bool is_locked) { initialized_ = is_locked; }
};

#endif  // LOGIN_MANAGER_MOCK_INSTALL_ATTRIBUTES_READER_H_
