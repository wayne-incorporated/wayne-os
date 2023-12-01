// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MODEMFWD_JOURNAL_H_
#define MODEMFWD_JOURNAL_H_

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>

#include "modemfwd/firmware_directory.h"
#include "modemfwd/modem_helper_directory.h"

namespace modemfwd {

class Journal {
 public:
  virtual ~Journal() = default;

  // We keep track of device id and possibly carrier id here instead of the
  // file path to handle the following case:
  // * The device loses power.
  // * When we come back up, a newer version of the component is loaded.
  // The file path to the relevant firmware has now changed, so we need to
  // be able to load from the new location.
  virtual void MarkStartOfFlashingFirmware(
      const std::vector<std::string>& firmware_types,
      const std::string& device_id,
      const std::string& carrier_id) = 0;
  virtual void MarkEndOfFlashingFirmware(const std::string& device_id,
                                         const std::string& carrier_id) = 0;
};

// Opens the journal at |journal_path|. If there was an operation in
// progress, that operation is restarted before the journal is returned.
std::unique_ptr<Journal> OpenJournal(const base::FilePath& journal_path,
                                     FirmwareDirectory* firmware_dir,
                                     ModemHelperDirectory* helper_dir);

}  // namespace modemfwd

#endif  // MODEMFWD_JOURNAL_H_
