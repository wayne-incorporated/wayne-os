// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "policy_utils/policy_writer.h"

#include <vector>

#include <base/files/file_util.h>
#include <base/json/json_writer.h>
#include <base/values.h>

namespace {

// Property name and corresponding file name for policies.
const char kPolicyDeviceAllowBluetooth[] = "DeviceAllowBluetooth";
const char kPolicyDeviceAllowBluetoothFileName[] =
    "device_allow_bluetooth.json";

const char kPolicyShowHomeButton[] = "ShowHomeButton";
const char kPolicyShowHomeButtonFileName[] = "show_home_bbuton.json";

const char kPolicyBookmarkBarEnabled[] = "BookmarkBarEnabled";
const char kPolicyBookmarkBarEnabledFileName[] = "bookmark_bar_enabled.json";

// Create all non-existent directories in path |full_path. Each directory is
// created with permission 0755. Return whether successful.
bool CreateDirectories(const base::FilePath& full_path) {
  std::vector<base::FilePath> subpaths;

  // Collect a list of all parent directories.
  base::FilePath last_path = full_path;
  subpaths.push_back(full_path);
  for (base::FilePath path = full_path.DirName();
       path.value() != last_path.value(); path = path.DirName()) {
    subpaths.push_back(path);
    last_path = path;
  }

  // Iterate through the parents and create the missing ones.
  for (std::vector<base::FilePath>::reverse_iterator i = subpaths.rbegin();
       i != subpaths.rend(); ++i) {
    if (!base::DirectoryExists(*i) && mkdir(i->value().c_str(), 0755) != 0) {
      return false;
    }
  }
  return true;
}

// Converts the given policy to a JSON string and writes it to file
// <dir_path>/<file_name>. Returns whether successul.
bool WritePolicyToFile(const base::Value::Dict& policy,
                       const base::FilePath& dir_path,
                       const char* file_name) {
  if (!file_name) {
    return false;
  }

  if (!CreateDirectories(dir_path))
    return false;

  std::string json_string;
  base::JSONWriter::Write(policy, &json_string);

  base::FilePath file_path = dir_path.Append(file_name);
  return base::WriteFile(file_path, json_string.data(), json_string.length()) ==
         json_string.length();
}

// Deletes the policy file <dir_path>/<file_name> if it exists. Returns whether
// successful.
bool DeletePolicyFile(const base::FilePath& dir_path, const char* file_name) {
  if (!file_name) {
    return false;
  }
  return base::DeleteFile(dir_path.Append(file_name));
}

}  // anonymous namespace

namespace policy_utils {

PolicyWriter::PolicyWriter(const std::string& dest_dir_path)
    : dest_dir_path_(dest_dir_path) {}

PolicyWriter::~PolicyWriter() {}

bool PolicyWriter::SetDeviceAllowBluetooth(bool is_allowed) const {
  base::Value::Dict policy;
  policy.Set(kPolicyDeviceAllowBluetooth, is_allowed);
  return WritePolicyToFile(policy, dest_dir_path_,
                           kPolicyDeviceAllowBluetoothFileName);
}

bool PolicyWriter::SetShowHomeButton(bool show) const {
  base::Value::Dict policy;
  policy.Set(kPolicyShowHomeButton, show);
  return WritePolicyToFile(policy, dest_dir_path_,
                           kPolicyShowHomeButtonFileName);
}

bool PolicyWriter::SetBookmarkBarEnabled(bool is_enabled) const {
  base::Value::Dict policy;
  policy.Set(kPolicyBookmarkBarEnabled, is_enabled);
  return WritePolicyToFile(policy, dest_dir_path_,
                           kPolicyBookmarkBarEnabledFileName);
}

bool PolicyWriter::ClearDeviceAllowBluetooth() const {
  return DeletePolicyFile(dest_dir_path_, kPolicyDeviceAllowBluetoothFileName);
}

bool PolicyWriter::ClearShowHomeButton() const {
  return DeletePolicyFile(dest_dir_path_, kPolicyShowHomeButtonFileName);
}

bool PolicyWriter::ClearBookmarkBarEnabled() const {
  return DeletePolicyFile(dest_dir_path_, kPolicyBookmarkBarEnabledFileName);
}
}  // namespace policy_utils
