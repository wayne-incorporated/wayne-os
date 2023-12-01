// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FLEX_ID_FLEX_ID_H_
#define FLEX_ID_FLEX_ID_H_

#include <optional>
#include <string>

#include <base/files/file_util.h>

namespace flex_id {

// This class is responsible for reading various sources to determine
// and save a unique machine identifier.
class FlexIdGenerator {
 public:
  explicit FlexIdGenerator(const base::FilePath& base_path);

  // Can be used to add a prefix to the flex_id.
  std::optional<std::string> AddFlexIdPrefix(const std::string& flex_id);

  // Reads the contents of var/lib/flex_id/flex_id which is
  // the flex_id.
  std::optional<std::string> ReadFlexId();

  // Reads the contents of var/lib/client_id/client_id which is
  // what flex_id was originally called.
  std::optional<std::string> TryClientId();

  // Reads the contents of mnt/stateful_partition/cloudready/client_id
  // which is the legacy CloudReady client_id
  std::optional<std::string> TryLegacy();

  // Reads the contents of sys/devices/virtual/dmi/id/product_serial
  // The serial is compared against known bad values and other criteria
  // If successful, the prefix is added and the result is returned
  std::optional<std::string> TrySerial();

  // Tries to find a hardware mac address from sys/class/net
  // The interfaces are compared against known good/bad names, addresses,
  // and what bus the device is on. If successful, the prefix is added
  // and the result is returned.
  std::optional<std::string> TryMac();

  // Reads the contents of proc/sys/kernel/random/uuid. This is a random id.
  // If successful, the prefix is added and the result is returned
  std::optional<std::string> TryUuid();

  // Writes the flex_id to var/lib/flex_id/flex_id
  // with a newline.
  bool WriteFlexId(const std::string& flex_id);

  // Tries to find the best flex_id in the order:
  // 1. Flex ID
  // 2. Legacy Client ID
  // 3. DMI Serial Number
  // 4. Hardware MAC Address
  // 5. Random UUID
  // The result is saved to var/lib/flex_id/flex_id
  std::optional<std::string> GenerateAndSaveFlexId();

 private:
  base::FilePath base_path_;
};

}  // namespace flex_id

#endif  // FLEX_ID_FLEX_ID_H_
