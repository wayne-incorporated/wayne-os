// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLCSERVICE_PREFS_H_
#define DLCSERVICE_PREFS_H_

#include <string>

#include <base/files/file_path.h>

#include "dlcservice/boot/boot_slot.h"
#include "dlcservice/dlc_base.h"

namespace dlcservice {

extern const char kDlcPrefVerified[];
extern const char kDlcPrefVerifiedValueFile[];
extern const char kDlcRootMount[];

// |Prefs| class can be used to persist key value pairs to disk.
class Prefs {
 public:
  // Initializes prefs with root as |prefs_root|.
  explicit Prefs(const base::FilePath& prefs_root);

  // Initializes prefs starting path using |SystemState::dlc_prefs_dir()| with
  // |DlcBase|'s DLC ID and |BootSlot::Slot|.
  Prefs(const DlcBase& dlc, BootSlot::Slot slot);

  // Sets the given |value| for |key|, creating the |key| if it did not exist.
  bool SetKey(const std::string& key, const std::string& value);

  // Gets the given |key|'s value into |value|. Returns false if |key| did not
  // exist.
  bool GetKey(const std::string& key, std::string* value);

  // Creates the given |key| with empty value.
  bool Create(const std::string& key);

  // Returns true if the |key| exists.
  bool Exists(const std::string& key);

  // Removes the |key|.
  bool Delete(const std::string& key);

 private:
  base::FilePath prefs_root_;

  Prefs(const Prefs&) = delete;
  Prefs& operator=(const Prefs&) = delete;
};

}  // namespace dlcservice

#endif  // DLCSERVICE_PREFS_H_
