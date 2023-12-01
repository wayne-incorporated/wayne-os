// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//
// Definitions for HPS host interface.
//
#ifndef HPS_HPS_REG_H_
#define HPS_HPS_REG_H_

#include <cstdint>

#define BIT(b) (1ULL << (b))

namespace hps {

// Memory bank numbers for the download operation
enum class HpsBank {
  kMcuFlash = 0,
  kSpiFlash = 1,
  kSocRom = 2,
};

// Register numbers for HPS module interface.
enum class HpsReg : uint8_t {
  kMagic = 0,
  kHwRev = 1,
  kSysStatus = 2,
  kSysCmd = 3,
  kBankReady = 5,
  kError = 6,
  kFeatEn = 7,
  kFeature0 = 8,
  kFeature1 = 9,
  kFirmwareVersionHigh = 10,
  kFirmwareVersionLow = 11,
  kFpgaBootCount = 12,
  kFpgaLoopCount = 13,
  kFpgaRomVersion = 14,
  kSpiFlashStatus = 15,
  kCameraConfig = 18,
  kStartCameraTest = 19,
  kOptionBytesConfig = 20,
  kPartIds = 21,
  kPreviousCrashMessage = 22,
  kFpgaCrashMessage = 23,
  kMax = 127,
};

// Register 2 (RO) - System status register.
enum R2 : uint16_t {
  kOK = BIT(0),
  kFault = BIT(1),
  kDeprecatedAVerify = BIT(2),  // Unused (formerly AVERIFY in stage0 v3)
  kStage0 = BIT(3),             // Stage0 running
  kWpOn = BIT(4),
  kWpOff = BIT(5),
  // Unused          BIT(6),
  // Unused          BIT(7),
  kStage1 = BIT(8),             // Stage1 running
  kAppl = BIT(9),               // Application running
  kCmdInProgress = BIT(10),     // Command in progress (often SPI flash hashing)
  kStage0Locked = BIT(11),      // Stage0 has been made read-only
  kStage0PermLocked = BIT(12),  // Stage0 has been made permanently read-only
  kOneTimeInit = BIT(13),       // one_time_init payload is running
};

// Register 3 (WO) - System command register.
enum R3 : uint16_t {
  kReset = BIT(0),
  kLaunch1 = BIT(1),
  kLaunchAppl = BIT(2),
  kEraseStage1 = BIT(3),
  kEraseSpiFlash = BIT(4),
};

// Register 7 (RW) - Feature enable bit mask.
enum R7 : uint16_t {
  kFeature0Enable = BIT(0),
  kFeature1Enable = BIT(1),
};

// Feature result registers (R8 & R9).
enum RFeat : uint16_t {
  kValid = BIT(15),  // Feature result is valid.
};

enum RError : uint16_t {
  kNone = 0,
  kHostI2cUnderrun = 0x0001,
  kMcuFlashWriteError = 0x0002,
  kPanic = 0x0004,
  kFpgaPanic = 0x0005,
  kFpgaException = 0x0006,
  kHostI2cBusError = 0x0008,
  kHostI2cOverrun = 0x0010,
  kCameraI2c = 0x0020,
  kCameraImageTimeout = 0x0021,
  kCameraUnexpectedId = 0x0022,
  kCameraUnexpectedReset = 0x0023,
  kSpiFlash = 0x0040,
  kHostI2cBadRequest = 0x0080,
  kBufferNotAvailable = 0x0100,
  kBufferOverrun = 0x0200,
  kSpiFlashNotVerified = 0x0400,
  kTfliteFailure = 0x0800,
  kSelfTestFailed = 0x1000,
  kFpgaMcuCommError = 0x2000,
  kFpgaTimeout = 0x4000,
  kStage1NotFound = 0x4001,
  kStage1TooOld = 0x4002,
  kStage1InvalidSignature = 0x4003,
  kInternal = 0x4004,
  kMcuFlashEcc = 0x4005,
  kMcuNmi = 0x4006,
};

inline constexpr uint16_t kHpsMagic = 0x9df2;
inline constexpr int kFeatures = 2;  // Maximum of 2 features at this stage.

// The interface allows up to 64 banks, but only 16 are
// usable at this stage because of the requirement to check
// if the bank is ready via a register.

inline constexpr int kNumBanks = 16;

inline uint8_t I2cMemWrite(uint8_t bank) {
  return (bank % kNumBanks) | 0;
}

inline uint8_t I2cReg(HpsReg reg) {
  return static_cast<uint8_t>(reg) | 0x80U;
}

struct FeatureResult {
  int8_t inference_result;
  bool valid;
};

inline bool operator==(const FeatureResult& lhs, const FeatureResult& rhs) {
  return lhs.inference_result == rhs.inference_result && lhs.valid == rhs.valid;
}
inline bool operator!=(const FeatureResult& lhs, const FeatureResult& rhs) {
  return !(lhs == rhs);
}

}  // namespace hps

#endif  // HPS_HPS_REG_H_
