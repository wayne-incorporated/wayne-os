// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HAMMERD_HAMMER_UPDATER_H_
#define HAMMERD_HAMMER_UPDATER_H_

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <metrics/metrics_library.h>

#include "hammerd/dbus_wrapper.h"
#include "hammerd/pair_utils.h"
#include "hammerd/update_fw.h"

namespace hammerd {

class HammerUpdater {
 public:
  // The result of the Run, RunLoop, RunOnce, .. methods.
  enum class RunStatus {
    kNoUpdate,
    kFatalError,
    kNeedReset,
    kNeedJump,
    kLostConnection,
    kInvalidFirmware,
    kTouchpadUpToDate,
    kTouchpadMismatched,
    kNeedLock,
  };

  enum class UpdateCondition {
    kNever,
    kMismatch,
    kAlways,
    kUnknown,
  };
  static UpdateCondition ToUpdateCondition(const std::string& s);

  // The internal state used for RunOnce method. Each flag indicates a task, or
  // an expectation at the next round. If the task or expectation is satisfied,
  // then reset the flag.
  struct TaskState {
    // Flags to indicate whether the sections should be updated. Reset them
    // after update is finished.
    bool update_ro;
    bool update_rw;
    bool update_tp;
    // Set the flag when the EC lacks entropy. Reset it after the entropy is
    // injected successfully.
    bool inject_entropy;
    // Set the flag when we lock RW at the previous round.
    bool post_rw_lock;
    // Set the flag when we jump to RW at the previous round.
    bool post_rw_jump;

    TaskState()
        : update_ro(false),
          update_rw(false),
          update_tp(false),
          inject_entropy(false),
          post_rw_lock(false),
          post_rw_jump(false) {}
    const std::string ToString();
  };

  HammerUpdater(const std::string& ec_image,
                const std::string& touchpad_image,
                const std::string& touchpad_product_id,
                const std::string& touchpad_fw_ver,
                uint16_t vendor_id,
                uint16_t product_id,
                const std::string& usb_path,
                bool at_boot,
                UpdateCondition update_condition);
  virtual ~HammerUpdater() = default;

  // Handle the whole update process, including pre-processing, main update
  // logic loop, and the post-processing.
  virtual RunStatus Run();
  // Handle the main update logic loop. For each round, it establishes the USB
  // connection, calls RunOnce() method, and runs some actions according the
  // returned status.
  virtual RunStatus RunLoop();
  // Handle the update logic from connecting to the EC to sending reset signal.
  // There is only one USB connection during each RunOnce() method call.
  virtual RunStatus RunOnce();

  // The post processing after the RW section is up to date.
  virtual RunStatus PostRWProcess();
  // Update RO section if the device is in dogfood mode.
  virtual RunStatus UpdateRO();
  // Pair with the hammer device.
  virtual RunStatus Pair();
  // Update the touchpad firmware via the virtual address.
  virtual RunStatus RunTouchpadUpdater();
  // Extract product_id and firmware version.
  static bool ParseTouchpadInfoFromFilename(const std::string& filename,
                                            std::string* touchpad_product_id,
                                            std::string* touchpad_fw_ver);
  // Setter for inject_entropy control flag in TestState.
  void SetInjectEntropyFlag(bool inject_entropy);

 protected:
  // Used in unittests to inject mock instance.
  HammerUpdater(const std::string& ec_image,
                const std::string& touchpad_image,
                const std::string& touchpad_product_id,
                const std::string& touchpad_fw_ver,
                const std::string& path,
                bool at_boot,
                UpdateCondition update_condition,
                std::unique_ptr<FirmwareUpdaterInterface> fw_updater,
                std::unique_ptr<PairManagerInterface> pair_manager,
                std::unique_ptr<DBusWrapperInterface> dbus_wrapper,
                std::unique_ptr<MetricsLibraryInterface> metrics);
  HammerUpdater(const HammerUpdater&) = delete;
  HammerUpdater& operator=(const HammerUpdater&) = delete;

  // Waits for hammer USB device ready. It is called after the whole updating
  // process to prevent invoking hammerd infinitely.
  void WaitUsbReady(HammerUpdater::RunStatus status);

  // Sends DBus kBaseFirmwareNeedUpdateSignal to notify other processes that
  // the RW section need to be updated.
  // Note the update condition should be "never".
  void NotifyNeedUpdate();
  // Sends DBus kBaseFirmwareUpdateStartedSignal to notify other processes that
  // the RW section will now be updated.
  // Note the update condition should not be "never".
  void NotifyUpdateStarted();
  // Sends DBus signal to notify other processes that the RW section is updated
  // successfully or failed.
  // Note the update condition should not be "never".
  void NotifyUpdateFinished(bool is_success);

  template <typename HammerUpdaterType>
  friend class HammerUpdaterTest;

 private:
  // The EC_image data to be updated.
  const std::string ec_image_;
  // The touchpad image data to be updated.
  const std::string touchpad_image_;
  // The touchpad firmware product id.
  const std::string touchpad_product_id_;
  // The touchpad firmware version.
  const std::string touchpad_fw_ver_;
  // A string of combined USB bus and port.
  const std::string usb_path_;
  // Set this flag when hammerd is triggered at boot time.
  const bool at_boot_;
  // The update mode. Leave as non-const for unittesting purposes.
  UpdateCondition update_condition_;
  // The sysfs path of the USB device.
  const base::FilePath base_path_;
  // The internal state used for RunOnce method.
  HammerUpdater::TaskState task_;
  // The main firmware updater.
  std::unique_ptr<FirmwareUpdaterInterface> fw_updater_;
  // The pairing manager.
  std::unique_ptr<PairManagerInterface> pair_manager_;
  // The DBus wrapper is used to send signals to other processes.
  std::unique_ptr<DBusWrapperInterface> dbus_wrapper_;
  // When we send a DBus signal to notify that the update process is starting,
  // we set this flag. After the whole process finishes, we will send another
  // DBus signal to notify whether the process succeeded or failed, and the flag
  // will be unset.
  bool dbus_notified_;
  // The UMA metrics object.
  std::unique_ptr<MetricsLibraryInterface> metrics_;

  // Utility functions for dealing with vendor and version strings.
  std::string VersionString(TouchpadInfo info);
  std::string VendorString(TouchpadInfo info);

  // Helper function to update RW section.
  HammerUpdater::RunStatus UpdateRW();
};

}  // namespace hammerd
#endif  // HAMMERD_HAMMER_UPDATER_H_
