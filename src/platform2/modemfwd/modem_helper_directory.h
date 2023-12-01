// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MODEMFWD_MODEM_HELPER_DIRECTORY_H_
#define MODEMFWD_MODEM_HELPER_DIRECTORY_H_

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <dbus/bus.h>

namespace modemfwd {

class ModemHelper;

class ModemHelperDirectory {
 public:
  virtual ~ModemHelperDirectory() = default;

  // Returns a weak pointer. Ensure users do not outlive the directory.
  virtual ModemHelper* GetHelperForDeviceId(const std::string& device_id) = 0;

  // Calls |callback| for each pair of {device_id, helper} known to the
  // ModemHelperDirectory.
  virtual void ForEachHelper(
      base::RepeatingCallback<void(const std::string&, ModemHelper*)>
          callback) = 0;
};

std::unique_ptr<ModemHelperDirectory> CreateModemHelperDirectory(
    const base::FilePath& directory,
    const std::string& variant,
    scoped_refptr<dbus::Bus> bus);

}  // namespace modemfwd

#endif  // MODEMFWD_MODEM_HELPER_DIRECTORY_H_
