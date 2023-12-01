// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MODEMFWD_MODEM_FLASHER_H_
#define MODEMFWD_MODEM_FLASHER_H_

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <base/functional/callback.h>
#include <brillo/errors/error.h>
#include <chromeos/switches/modemfwd_switches.h>

#include "modemfwd/firmware_directory.h"
#include "modemfwd/journal.h"
#include "modemfwd/modem.h"
#include "modemfwd/notification_manager.h"
#include "upstart/dbus-proxies.h"

namespace modemfwd {

// ModemFlasher contains all of the logic to make decisions about whether
// or not it should flash new firmware onto the modem.
class ModemFlasher {
 public:
  ModemFlasher(FirmwareDirectory* firmware_directory,
               std::unique_ptr<Journal> journal,
               NotificationManager* notification_mgr,
               Metrics* metrics);
  ModemFlasher(const ModemFlasher&) = delete;
  ModemFlasher& operator=(const ModemFlasher&) = delete;

  // Returns a callback that should be executed when the modem reappears.
  // |err| is set if an error occurred.
  base::OnceClosure TryFlash(Modem* modem,
                             scoped_refptr<dbus::Bus> bus,
                             brillo::ErrorPtr* err);

  // This function is the same as TryFlash, but it sets the variant to be used.
  // |err| is set if an error occurred.
  base::OnceClosure TryFlashForTesting(Modem* modem,
                                       const std::string& variant,
                                       brillo::ErrorPtr* err);

 private:
  class FlashState {
   public:
    FlashState() = default;
    ~FlashState() = default;

    void OnFlashFailed() { tries_--; }
    bool ShouldFlash() const { return tries_ > 0; }

    void OnFlashedFirmware(const std::string& type,
                           const base::FilePath& path) {
      if (type == kFwCarrier) {
        last_carrier_fw_flashed_ = path;
        return;
      }
      flashed_fw_types_.insert(type);
    }

    bool ShouldFlashFirmware(const std::string& type,
                             const base::FilePath& path) {
      if (type == kFwCarrier)
        return last_carrier_fw_flashed_ != path;
      return flashed_fw_types_.count(type) == 0;
    }

    void OnCarrierSeen(const std::string& carrier_id) {
      if (carrier_id == last_carrier_id_)
        return;

      last_carrier_id_ = carrier_id;
      flashed_fw_types_.clear();
    }

    // Used to determine if any FW was installed before reporting metrics.
    bool fw_flashed_ = false;
    // Used to preserve the combination of firmware types flashed before
    // reporting metrics.
    uint32_t fw_types_flashed_ = 0;

   private:
    // Unlike carrier firmware, we should usually successfully flash the main
    // firmware at most once per boot. In the past vendors have failed to
    // update the version that the firmware reports itself as so we can mitigate
    // some of the potential issues by recording which modems we have deemed
    // don't need updates or were already updated and avoid checking them again.
    //
    // We should retry flashing the main firmware if the carrier changes since
    // we might have different main firmware versions. As such, when we see a
    // new carrier, clear the flashed types for this modem.
    std::set<std::string> flashed_fw_types_;
    std::string last_carrier_id_;

    // For carrier firmware, once we've tried to upgrade versions on a
    // particular modem without changing carriers, we should not try to upgrade
    // versions again (but should still flash if the carrier is different) to
    // avoid the same problem as the above. Keep track of the last carrier
    // firmware we flashed so we don't flash twice in a row.
    base::FilePath last_carrier_fw_flashed_;

    // If we fail to flash firmware, we will retry once, but after that we
    // should stop flashing the modem to prevent us from trying it over and
    // over.
    static const int kDefaultTries = 2;
    int tries_ = kDefaultTries;
  };

  base::FilePath GetFirmwarePath(const FirmwareFileInfo& info);

  // Notify UpdateFirmwareComplete failure and reset the |fw_flashed_| flag.
  void ProcessFailedToPrepareFirmwareFile(const base::Location& code_location,
                                          FlashState* flash_state,
                                          const std::string& firmware_path,
                                          brillo::ErrorPtr* err);

  uint32_t GetFirmwareTypesForMetrics(std::vector<FirmwareConfig> flash_cfg);

  std::unique_ptr<Journal> journal_;

  std::map<std::string, FlashState> modem_info_;

  // Owned by Daemon
  FirmwareDirectory* firmware_directory_;
  NotificationManager* notification_mgr_;
  Metrics* metrics_;
};

}  // namespace modemfwd

#endif  // MODEMFWD_MODEM_FLASHER_H_
