// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
 * Simulated HPS hardware device.
 */
#include "hps/hal/fake_dev.h"

#include <iostream>
#include <map>

#include <base/check.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>

#include "hps/hps_reg.h"
#include "hps/utils.h"

namespace hps {

class FakeWakeLock : public WakeLock {
 public:
  explicit FakeWakeLock(FakeDev& dev) : dev_(dev) {
    if (dev_.wake_lock_count_ == 0) {
      // Reset back to stage0 as if the device had been power-cycled.
      dev_.SetStage(FakeDev::Stage::kStage0);
    }
    dev_.wake_lock_count_++;
  }

  ~FakeWakeLock() override {
    dev_.wake_lock_count_--;
    DCHECK_GE(dev_.wake_lock_count_, 0);
    if (!dev_.wake_lock_count_ && dev_.power_on_failure_count_)
      dev_.power_on_failure_count_--;
  }

  bool supports_power_management() override { return true; }

 private:
  FakeDev& dev_;
};

bool FakeDev::ReadDevice(uint8_t cmd, uint8_t* data, size_t len) {
  DCHECK(wake_lock_count_);
  if (power_on_failure_count_)
    return false;
  // Clear the whole buffer.
  memset(data, 0, len);
  if ((cmd & 0x80) != 0) {
    // Register read.
    std::optional<uint16_t> result =
        this->ReadRegister(static_cast<HpsReg>(cmd & 0x7F));
    if (!result)
      return false;
    // Store the value of the register into the buffer.
    if (len > 0) {
      data[0] = (result.value() >> 8) & 0xFF;
      if (len > 1) {
        data[1] = result.value() & 0xFF;
      }
    }
  } else {
    // No memory read.
    return false;
  }
  return true;
}

bool FakeDev::WriteDevice(uint8_t cmd, const uint8_t* data, size_t len) {
  DCHECK(wake_lock_count_);
  if (power_on_failure_count_)
    return false;
  if ((cmd & 0x80) != 0) {
    if (len != 0) {
      // Register write.
      uint16_t value = static_cast<uint16_t>(data[0] << 8);
      if (len > 1) {
        value |= data[1];
      }
      return this->WriteRegister(static_cast<HpsReg>(cmd & 0x7F), value);
    }
  } else if ((cmd & 0xC0) == 0) {
    // Memory write.
    return this->WriteMemory(static_cast<HpsBank>(cmd & 0x3F), data, len);
  } else {
    // Unknown command.
    return false;
  }
  return true;
}

// Switch to the stage selected, and set up any flags or config.
// Depending on the stage, the HPS module supports different
// registers and attributes.
void FakeDev::SetStage(Stage s) {
  this->stage_ = s;
  switch (s) {
    case Stage::kStage0:
      this->bank_ = BIT(0);
      this->fault_ = RError::kNone;
      this->feature_on_ = 0;
      break;
    case Stage::kStage1:
      this->bank_ = BIT(1) | BIT(2);
      break;
    case Stage::kAppl:
      this->bank_ = 0;
      break;
  }
}

std::optional<uint16_t> FakeDev::ReadRegister(HpsReg reg) {
  uint16_t v = 0;
  switch (reg) {
    case HpsReg::kMagic:
      v = kHpsMagic;
      break;
    case HpsReg::kHwRev:
      if (this->stage_ == Stage::kStage0) {
        v = 0x0104;  // Version return in stage0.
      }
      break;
    case HpsReg::kSysStatus:
      if (Flag(Flags::kFailStatusRegRead)) {
        Clear(Flags::kFailStatusRegRead);
        return std::nullopt;
      }
      v = hps::R2::kOK;
      if (this->fault_ != RError::kNone) {
        v |= hps::R2::kFault;
      }
      if (this->stage_ == Stage::kStage0) {
        v |= hps::R2::kStage0;
      }
      if (this->Flag(Flags::kWpOff)) {
        v |= hps::R2::kWpOff;
      } else {
        v |= hps::R2::kWpOn;
      }
      if (this->stage_ == Stage::kStage1) {
        v |= hps::R2::kStage1;
      }
      if (this->stage_ == Stage::kAppl) {
        v |= hps::R2::kAppl;
      }
      break;

    case HpsReg::kBankReady:
      v = this->bank_;
      break;

    case HpsReg::kFeature0:
      if (this->feature_on_ & hps::R7::kFeature0Enable) {
        v = this->f0_result_;
      }
      break;

    case HpsReg::kFeature1:
      if (this->feature_on_ & hps::R7::kFeature1Enable) {
        v = this->f1_result_;
      }
      break;

    case HpsReg::kFirmwareVersionHigh:
      // Firmware version, only returned in stage1.
      if (this->stage_ == Stage::kStage1) {
        v = static_cast<uint16_t>(firmware_version_ >> 16);
      } else {
        v = 0xFFFF;
      }
      break;

    case HpsReg::kFirmwareVersionLow:
      // Firmware version, only returned in stage1.
      if (this->stage_ == Stage::kStage1) {
        v = static_cast<uint16_t>(firmware_version_ & 0xFFFF);
      } else {
        v = 0xFFFF;
      }
      break;

    case HpsReg::kError:
      v = this->fault_;
      break;

    case HpsReg::kSysCmd:
    case HpsReg::kFeatEn:
    case HpsReg::kFpgaBootCount:
    case HpsReg::kFpgaLoopCount:
    case HpsReg::kFpgaRomVersion:
    case HpsReg::kSpiFlashStatus:
    case HpsReg::kCameraConfig:
    case HpsReg::kStartCameraTest:
    case HpsReg::kOptionBytesConfig:
    case HpsReg::kPartIds:
    case HpsReg::kPreviousCrashMessage:
    case HpsReg::kFpgaCrashMessage:
    case HpsReg::kMax:
      break;
  }
  VLOG(2) << "Read reg " << HpsRegInfo(reg)->name << " value " << v;
  return v;
}

bool FakeDev::WriteRegister(HpsReg reg, uint16_t value) {
  VLOG(2) << "Write reg " << HpsRegInfo(reg)->name << " value " << value;
  // Ignore everything except the command register.
  switch (reg) {
    case HpsReg::kSysCmd:
      if (value & hps::R3::kReset) {
        this->SetStage(Stage::kStage0);
      } else if (value & hps::R3::kLaunch1) {
        // Only valid in stage0
        if (this->stage_ == Stage::kStage0) {
          // Only boot if stage1 was valid, or WP is off
          if (this->Flag(Flags::kStage1NotVerified) &&
              !this->Flag(Flags::kWpOff)) {
            this->fault_ = hps::RError::kStage1InvalidSignature;
          } else if (this->Flag(Flags::kFlashEccError)) {
            this->Clear(Flags::kFlashEccError);
            this->fault_ = hps::RError::kMcuFlashEcc;
          } else {
            this->SetStage(Stage::kStage1);
          }
        }
      } else if (value & hps::R3::kLaunchAppl) {
        // Only valid in stage1
        if (this->stage_ == Stage::kStage1) {
          // only boot valid spi flash, else set fault bit
          if (this->Flag(Flags::kSpiNotVerified)) {
            this->fault_ = hps::RError::kSpiFlashNotVerified;
          } else {
            this->SetStage(Stage::kAppl);
          }
        }
      } else if (value & hps::R3::kEraseStage1) {
        // Only valid in stage0
        if (this->stage_ == Stage::kStage0) {
          this->bank_erased_[HpsBank::kMcuFlash] = true;
        }
      } else if (value & hps::R3::kEraseSpiFlash) {
        // Only valid in stage1
        if (this->stage_ == Stage::kStage1) {
          this->bank_erased_[HpsBank::kSpiFlash] = true;
          this->bank_erased_[HpsBank::kSocRom] = true;
        }
      }
      break;

    case HpsReg::kFeatEn:
      // Set the feature enable bit mask.
      this->feature_on_ = value;
      break;

    case HpsReg::kMagic:
    case HpsReg::kHwRev:
    case HpsReg::kSysStatus:
    case HpsReg::kBankReady:
    case HpsReg::kError:
    case HpsReg::kFeature0:
    case HpsReg::kFeature1:
    case HpsReg::kFirmwareVersionHigh:
    case HpsReg::kFirmwareVersionLow:
    case HpsReg::kFpgaBootCount:
    case HpsReg::kFpgaLoopCount:
    case HpsReg::kFpgaRomVersion:
    case HpsReg::kSpiFlashStatus:
    case HpsReg::kCameraConfig:
    case HpsReg::kStartCameraTest:
    case HpsReg::kOptionBytesConfig:
    case HpsReg::kPartIds:
    case HpsReg::kPreviousCrashMessage:
    case HpsReg::kFpgaCrashMessage:
    case HpsReg::kMax:
      break;
  }
  return true;
}

// Returns the number of bytes written.
// The length includes 4 bytes of prepended address.
bool FakeDev::WriteMemory(HpsBank bank, const uint8_t* data, size_t len) {
  if (this->Flag(Flags::kMemFail)) {
    return false;
  }
  // Don't allow writes that exceed the max block size.
  if (len > (this->block_size_b_ + sizeof(uint32_t))) {
    return false;
  }
  // Bank must be explicitly erased before writing.
  if (!this->bank_erased_[bank]) {
    return false;
  }
  switch (this->stage_) {
    case Stage::kStage0:
      // Stage0 allows the MCU flash to be written.
      if (bank == HpsBank::kMcuFlash) {
        this->bank_len_[bank] += len - sizeof(uint32_t);
        // Check if the fake needs to reset the not-verified bit.
        if (this->Flag(Flags::kResetApplVerification)) {
          this->Clear(Flags::kStage1NotVerified);
        }
        // Check if the fake should increment the version.
        if (this->Flag(Flags::kIncrementVersion)) {
          this->Clear(Flags::kIncrementVersion);
          this->firmware_version_++;
        }
        return true;
      }
      break;
    case Stage::kStage1:
      // Stage1 allows the SPI flash to be written.
      if (bank == HpsBank::kSpiFlash || bank == HpsBank::kSocRom) {
        this->bank_len_[bank] += len - sizeof(uint32_t);
        // Check if the fake needs to reset the not-verified bit.
        if (this->Flag(Flags::kResetSpiVerification)) {
          this->Clear(Flags::kSpiNotVerified);
        }
        return true;
      }
      break;
    case Stage::kAppl:
      break;
  }
  return false;
}

size_t FakeDev::GetBankLen(hps::HpsBank bank) {
  return this->bank_len_[bank];
}

std::unique_ptr<WakeLock> FakeDev::CreateWakeLock() {
  return std::make_unique<FakeWakeLock>(*this);
}

}  // namespace hps
