// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MODEMFWD_MODEM_HELPER_DIRECTORY_STUB_H_
#define MODEMFWD_MODEM_HELPER_DIRECTORY_STUB_H_

#include <map>
#include <string>

#include "modemfwd/modem_helper_directory.h"

namespace modemfwd {

class ModemHelperDirectoryStub : public ModemHelperDirectory {
 public:
  ModemHelperDirectoryStub() = default;
  ModemHelperDirectoryStub(const ModemHelperDirectoryStub&) = delete;
  ModemHelperDirectoryStub& operator=(const ModemHelperDirectoryStub&) = delete;

  void AddHelper(const std::string& device_id, ModemHelper* helper) {
    helpers_[device_id] = helper;
  }

  // ModemHelperDirectory overrides.
  ModemHelper* GetHelperForDeviceId(const std::string& device_id) {
    auto it = helpers_.find(device_id);
    if (it == helpers_.end())
      return nullptr;
    return it->second;
  }

  void ForEachHelper(base::RepeatingCallback<void(const std::string&,
                                                  ModemHelper*)> callback) {
    for (const auto& entry : helpers_)
      callback.Run(entry.first, entry.second);
  }

 private:
  std::map<std::string, ModemHelper*> helpers_;
};

}  // namespace modemfwd

#endif  // MODEMFWD_MODEM_HELPER_DIRECTORY_STUB_H_
