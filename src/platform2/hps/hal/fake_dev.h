// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
 * Fake device for HPS testing.
 */
#ifndef HPS_HAL_FAKE_DEV_H_
#define HPS_HAL_FAKE_DEV_H_

#include <map>
#include <memory>

#include "hps/dev.h"
#include "hps/hps_reg.h"

namespace hps {

/*
 * FakeDev is an class that when started, spawns a thread to
 * asynchronously process register reads/writes and memory writes to
 * simulate the HPS hardware.
 * A separate thread is used to simulate the latency and concurrency of
 * the real device.
 *
 * A set of flags defines behaviour of the device (such as forced errors etc.).
 */
class FakeDev : public DevInterface {
 public:
  FakeDev() { this->SetStage(Stage::kStage0); }
  // Flags for controlling behaviour. Multiple flags can be set,
  // controlling how the fake responds under test conditions.
  enum class Flags {
    // Set MCU RW not verified status bit.
    kStage1NotVerified = 1,
    // Set SPI flash not verified status bit.
    kSpiNotVerified = 2,
    // Set WP bit as off.
    kWpOff = 3,
    // Fail any memory writes.
    kMemFail = 4,
    // If MCU download occurs, reset the RW not-verified flag.
    kResetApplVerification = 5,
    // If SPI download occurs, reset the SPI not-verified flag.
    kResetSpiVerification = 6,
    // When a RW download occurs, increment the firmware version number.
    kIncrementVersion = 7,
    // Set MCU flash ECC error bit when launching stage1.
    kFlashEccError = 8,
    // Reading the status register will fail once.
    kFailStatusRegRead = 9,
  };
  bool ReadDevice(uint8_t cmd, uint8_t* data, size_t len) override;
  bool WriteDevice(uint8_t cmd, const uint8_t* data, size_t len) override;
  size_t BlockSizeBytes() override { return this->block_size_b_; }
  std::unique_ptr<WakeLock> CreateWakeLock() override;

  void SkipBoot() { this->SetStage(Stage::kAppl); }
  void Set(Flags f) {
    this->flags_ |= static_cast<uint16_t>(1 << static_cast<int>(f));
  }
  void Clear(Flags f) {
    this->flags_ &= ~static_cast<uint16_t>(1 << static_cast<int>(f));
  }
  void SetVersion(uint32_t version) { this->firmware_version_ = version; }
  void SetBlockSizeBytes(size_t sz) { this->block_size_b_ = sz; }
  void SetF0Result(int8_t result, bool valid) {
    this->f0_result_ =
        (valid ? hps::RFeat::kValid : 0) | static_cast<uint8_t>(result);
  }
  void SetF1Result(int8_t result, bool valid) {
    this->f1_result_ =
        (valid ? hps::RFeat::kValid : 0) | static_cast<uint8_t>(result);
  }
  size_t GetBankLen(hps::HpsBank bank);
  void SetPowerOnFailureCount(int n) { power_on_failure_count_ = n; }
  // Return a DevInterface accessing the simulator.
  std::unique_ptr<DevInterface> CreateDevInterface();

 private:
  friend class FakeWakeLock;

  std::optional<uint16_t> ReadRegister(HpsReg r);
  bool WriteRegister(HpsReg r, uint16_t v);
  bool WriteMemory(HpsBank bank, const uint8_t* mem, size_t len);
  bool Flag(Flags f) {
    return (this->flags_ & (1 << static_cast<int>(f))) != 0;
  }
  // Current stage (phase) of the device.
  // The device behaves differently in different stages.
  enum class Stage {
    kStage0,
    kStage1,
    kAppl,
  };
  void SetStage(Stage s);
  std::map<HpsBank, size_t> bank_len_;   // Count of writes to banks.
  std::map<HpsBank, bool> bank_erased_;  // Whether bank has been erased
  Stage stage_;                          // Current stage of the device
  RError fault_ = RError::kNone;         // Fault (error) value
  uint16_t feature_on_ = 0;              // Enabled features.
  uint16_t bank_ = 0;                    // Current memory bank readiness
  uint16_t flags_ = 0;                   // Behaviour flags
  uint32_t firmware_version_ = 0;        // Firmware version
  size_t block_size_b_ = 256;            // Write block size.
  uint16_t f0_result_ = 0;               // Register value for feature 0
  uint16_t f1_result_ = 0;               // Register value for feature 1
  int wake_lock_count_ = 0;
  int power_on_failure_count_ = 0;
};

}  // namespace hps

#endif  // HPS_HAL_FAKE_DEV_H_
