// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Main HPS class.

#include <algorithm>
#include <fstream>
#include <optional>
#include <vector>

#include <base/strings/string_number_conversions.h>
#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <base/timer/elapsed_timer.h>
#include <lzma.h>

#include "hps/hps_impl.h"
#include "hps/hps_reg.h"
#include "hps/utils.h"

namespace hps {
namespace {

// Observed times are
// MCU: ~4ms for a normal write, ~27ms for a erase write
// SPI: 3ms for a normal write, 250ms for a erase write
// 5000ms for the full erase
// Theoretical max time for SPI flash full erase is 120s
// Set the sleep to ~1/5 of the normal time, and the timeout to 2x the
// expected max time. TODO(evanbenn) only do the long timeout for the
// first spi write.
static constexpr base::TimeDelta kBankReadySleep = base::Microseconds(500);
static constexpr base::TimeDelta kBankReadyTimeout = base::Seconds(240);

// After reset, we poll the magic number register for this long.
// Stage0 comes out of reset and responds on I2C in under 1ms,
// but launching stage1 takes around 1000ms due to signature validation.
// The magic number check is used in both situations.
static constexpr base::TimeDelta kMagicSleep = base::Milliseconds(100);
static constexpr base::TimeDelta kMagicTimeout = base::Milliseconds(3000);

// After requesting application launch, we must wait for signature verification.
// Expected time is around 4200ms.
static constexpr base::TimeDelta kApplTimeout = base::Milliseconds(6000);
static constexpr base::TimeDelta kApplSleep = base::Milliseconds(200);

// Time for letting the sensor settle after powering it off.
static constexpr base::TimeDelta kPowerOffDelay = base::Milliseconds(100);

// If the system is suspended for longer than this, we consider it a system
// suspend event.
static constexpr base::TimeDelta kSuspendThreshold = base::Milliseconds(1000);

// Special exit code to prevent upstart respawning us and crash
// service-failure-hpsd from being uploaded. See normal exit.
static constexpr int kNoRespawnExit = 5;

// How many "transient" errors we will try to recover from with a power cycle
// before declaring defeat.
static constexpr int kMaxTransientErrors = 100;

base::TimeDelta GetTime(clockid_t clk_id) {
  struct timespec ts = {};
  CHECK_EQ(clock_gettime(clk_id, &ts), 0);
  return base::TimeDelta::FromTimeSpec(ts);
}

}  // namespace

// Initialise the firmware parameters.
void HPS_impl::Init(uint32_t stage1_version,
                    const base::FilePath& mcu,
                    const base::FilePath& fpga_bitstream,
                    const base::FilePath& fpga_app_image) {
  this->required_stage1_version_ = stage1_version;
  this->mcu_blob_ = mcu;
  this->fpga_bitstream_ = fpga_bitstream;
  this->fpga_app_image_ = fpga_app_image;
}

// Attempt the boot sequence
void HPS_impl::Boot() {
  // Make sure blobs are set etc.
  if (this->mcu_blob_.empty() || this->fpga_bitstream_.empty() ||
      this->fpga_app_image_.empty()) {
    LOG(FATAL) << "No HPS firmware to download.";
  }

  this->boot_start_suspend_time_ = GetSystemSuspendTime();

  // If the boot process sent an update, reboot and try again
  // A full update takes 3 boots, so try 3 times.
  constexpr int kMaxBootAttempts = 3;
  for (int i = 0; i < kMaxBootAttempts; ++i) {
    if (!this->Reboot()) {
      LOG(INFO) << "Reboot failed, retrying";
      i = -1;
      continue;
    }
    if (!i)
      this->boot_start_time_ = base::TimeTicks::Now();

    switch (this->TryBoot()) {
      case BootResult::kOk:
        LOG(INFO) << "HPS device booted";
        return;
      case BootResult::kUpdate:
        LOG(INFO) << "Update sent, rebooting";
        continue;
      case BootResult::kRetry: {
        LOG(INFO) << "Transient boot failure, retrying";
        i = -1;
        continue;
      }
    }
  }
  OnFatalError(FROM_HERE, "Boot failure, too many updates.");
}

bool HPS_impl::Enable(uint8_t feature) {
  DCHECK(wake_lock_);
  // Only 2 features available at the moment.
  if (feature >= kFeatures) {
    LOG(ERROR) << "Enabling unknown feature (" << static_cast<int>(feature)
               << ")";
    return false;
  }
  // Check the application is enabled and running.
  std::optional<uint16_t> status = this->device_->ReadReg(HpsReg::kSysStatus);
  if (!status || !(status.value() & R2::kAppl)) {
    LOG(ERROR) << "Module not ready for feature control";
    return false;
  }
  this->feat_enabled_ |= 1 << feature;
  // Write the enable feature mask.
  return this->device_->WriteReg(HpsReg::kFeatEn, this->feat_enabled_);
}

bool HPS_impl::Disable(uint8_t feature) {
  DCHECK(wake_lock_);
  if (feature >= kFeatures) {
    LOG(ERROR) << "Disabling unknown feature (" << static_cast<int>(feature)
               << ")";
    return false;
  }
  // Check the application is enabled and running.
  std::optional<uint16_t> status = this->device_->ReadReg(HpsReg::kSysStatus);
  if (!status || !(status.value() & R2::kAppl)) {
    LOG(ERROR) << "Module not ready for feature control";
    return false;
  }
  this->feat_enabled_ &= ~(1 << feature);
  // Write the enable feature mask.
  return this->device_->WriteReg(HpsReg::kFeatEn, this->feat_enabled_);
}

FeatureResult HPS_impl::Result(int feature) {
  DCHECK(wake_lock_);
  // Check the application is enabled and running.
  std::optional<uint16_t> status = this->device_->ReadReg(HpsReg::kSysStatus);
  if (!status || !(status.value() & R2::kAppl)) {
    return {.valid = false};
  }
  // Check that feature is enabled.
  if (((1 << feature) & this->feat_enabled_) == 0) {
    return {.valid = false};
  }
  std::optional<uint16_t> hps_result = std::nullopt;
  switch (feature) {
    case 0:
      hps_result = this->device_->ReadReg(HpsReg::kFeature0);
      break;
    case 1:
      hps_result = this->device_->ReadReg(HpsReg::kFeature1);
      break;
  }
  if (!hps_result) {
    return {.valid = false};
  }
  // TODO(slangley): Clean this up when we introduce sequence numbers for
  // inference results.
  FeatureResult result;
  result.valid = (hps_result.value() & RFeat::kValid) == RFeat::kValid;
  hps_metrics_->SendImageValidity(result.valid);

  // The lower 8 bits are an int8_t.
  // We are extracting that byte here, not converting the uint16_t.
  result.inference_result = static_cast<int8_t>(hps_result.value() & 0xFF);
  return result;
}

// Attempt the boot sequence:
// Check stage0 flags, send a MCU update, fail or continue
// Check stage1 flags, fail or continue
// Check stage2 flags, send a SPI update or continue
// returns BootResult::kOk if booting completed
// returns BootResult::kUpdate if an update was sent
// returns BootResult::kRetry if we detect a transient error.
// else returns BootResult::kFail
hps::HPS_impl::BootResult HPS_impl::TryBoot() {
  // Inspect stage0 flags and either fail, update, or launch stage1 and continue
  switch (this->CheckStage0()) {
    case BootResult::kOk:
      VLOG(1) << "Launching stage 1";
      if (!this->device_->WriteReg(HpsReg::kSysCmd, R3::kLaunch1)) {
        OnFatalError(FROM_HERE, "Launch stage 1 failed");
      }
      break;
    // TODO(b/227977336): this will no longer be reachable when we drop support
    // for stage0 v3.
    case BootResult::kUpdate:
      if (mcu_update_sent_) {
        LOG(ERROR) << "Failed to boot after MCU update, giving up";
        hps_metrics_->SendHpsTurnOnResult(
            HpsTurnOnResult::kMcuUpdatedThenFailed,
            base::TimeTicks::Now() - this->boot_start_time_);
        exit(kNoRespawnExit);
      }
      mcu_update_sent_ = true;
      SendStage1Update();
      return BootResult::kUpdate;
    case BootResult::kRetry:
      return BootResult::kRetry;
  }

  // Inspect stage1 flags and either fail, update, or launch application and
  // continue
  switch (this->CheckStage1()) {
    case BootResult::kOk:
      VLOG(1) << "Launching Application";
      if (!this->device_->WriteReg(HpsReg::kSysCmd, R3::kLaunchAppl)) {
        OnFatalError(FROM_HERE, "Launch Application failed");
      }
      break;
    case BootResult::kUpdate:
      if (mcu_update_sent_) {
        LOG(ERROR) << "Failed to launch stage1 after MCU update, giving up";
        hps_metrics_->SendHpsTurnOnResult(
            HpsTurnOnResult::kMcuUpdatedThenFailed,
            base::TimeTicks::Now() - this->boot_start_time_);
        exit(kNoRespawnExit);
      }
      mcu_update_sent_ = true;
      VLOG(1) << "Rebooting back to stage0 before sending update";
      this->Reboot();
      if (!CheckMagic()) {
        hps_metrics_->SendHpsTurnOnResult(
            HpsTurnOnResult::kNoResponse,
            base::TimeTicks::Now() - this->boot_start_time_);
        OnFatalError(FROM_HERE, "Timeout waiting for stage0 magic number");
      }
      SendStage1Update();
      return BootResult::kUpdate;
    case BootResult::kRetry:
      return BootResult::kRetry;
  }

  // Inspect application flags and either fail, send an update, or succeed
  switch (this->CheckApplication()) {
    case BootResult::kOk:
      VLOG(1) << "Application Running";
      return BootResult::kOk;
    case BootResult::kUpdate:
      if (spi_update_sent_) {
        LOG(ERROR) << "Failed to boot after SPI update, giving up";
        hps_metrics_->SendHpsTurnOnResult(
            HpsTurnOnResult::kSpiUpdatedThenFailed,
            base::TimeTicks::Now() - this->boot_start_time_);
        exit(kNoRespawnExit);
      }
      spi_update_sent_ = true;
      SendApplicationUpdate();
      return BootResult::kUpdate;
    case BootResult::kRetry:
      return BootResult::kRetry;
  }
}

// Returns true if the device replies with the expected magic number in time.
// Attempts are made for kMagicTimeout time, with kMagicSleep delays between
// failures. Retries are only done for failed reads, not incorrect
// responses.
bool HPS_impl::CheckMagic() {
  base::ElapsedTimer timer;
  for (;;) {
    std::optional<uint16_t> magic = this->device_->ReadReg(HpsReg::kMagic);
    // Note that we don't treat a read failure here as a retryable transient
    // error, but rely on the caller to map a failure to an appropriate error.
    // In general failure to read the magic register is a fatal error, because
    // even a v3 stage0 should come online before this loop times out.
    if (!magic) {
      if (timer.Elapsed() < kMagicTimeout) {
        Sleep(kMagicSleep);
        continue;
      } else {
        return false;
      }
    } else if (magic == kHpsMagic) {
      VLOG(1) << "Good magic number after " << timer.Elapsed().InMilliseconds()
              << "ms";
      return true;
    } else {
      hps_metrics_->SendHpsTurnOnResult(
          HpsTurnOnResult::kBadMagic,
          base::TimeTicks::Now() - this->boot_start_time_);
      OnFatalError(FROM_HERE, base::StringPrintf("Bad magic number 0x%04x",
                                                 magic.value()));
    }
  }
}

// Check stage0 status:
// Check status flags.
// Read and store kHwRev.
// Check stage1 verification and version.
// Return BootResult::kOk if booting should continue.
// Return BootResult::kUpdate if an update should be sent.
// Return BootResult::kRetry if we detect a transient error.
hps::HPS_impl::BootResult HPS_impl::CheckStage0() {
  if (!CheckMagic()) {
    hps_metrics_->SendHpsTurnOnResult(
        HpsTurnOnResult::kNoResponse,
        base::TimeTicks::Now() - this->boot_start_time_);
    OnTransientBootFault(FROM_HERE, "Timeout waiting for stage0 magic number");
    return BootResult::kRetry;
  }

  std::optional<uint16_t> status = this->device_->ReadReg(HpsReg::kSysStatus);
  if (!status) {
    // TODO(evanbenn) log a metric
    OnTransientBootFault(FROM_HERE, "ReadReg failure");
    return BootResult::kRetry;
  }

  if (status.value() & R2::kFault || !(status.value() & R2::kOK)) {
    OnBootFault(FROM_HERE);
  }

  std::optional<uint16_t> hwrev = this->device_->ReadReg(HpsReg::kHwRev);
  if (!hwrev) {
    // TODO(evanbenn) log a metric
    OnTransientBootFault(FROM_HERE, "Failed to read hwrev");
    return BootResult::kRetry;
  }
  this->hw_rev_ = hwrev.value();

  if ((this->hw_rev_ & 0xff) >= 4) {
    // From version 4, stage0 does not validate stage1 after reset, nor does it
    // report the stage1 version. Instead it validates+launches stage1 when the
    // 'launch1' command is sent below.
    // It means we don't need to pay attention to the WP state, nor can we
    // determine whether a stage1 update is needed here. So there is nothing
    // more to do.
    return BootResult::kOk;
  }

  // Old logic for stage0 version 3 and earlier follows.
  // TODO(b/227977336): delete this when Taeko DVT is no longer in use.

  bool write_protect_off = status.value() & R2::kWpOff;
  VLOG_IF(1, write_protect_off) << "kWpOff, ignoring verified bits";

  // When write protect is off we ignore the verified signal.
  // When write protect is not off we update if there is no verified signal.
  if (!write_protect_off && !(status.value() & R2::kDeprecatedAVerify)) {
    // Stage1 not verified, so need to update it.
    LOG(INFO) << "Stage1 flash not verified";
    hps_metrics_->SendHpsTurnOnResult(
        HpsTurnOnResult::kMcuNotVerified,
        base::TimeTicks::Now() - this->boot_start_time_);
    return BootResult::kUpdate;
  }

  // Verified, so now check the version. If it is different, update it.
  return this->CheckStage1Version();
}

// Checks that stage1 version matches the version we expected.
// Returns BootResult::kOk if it does.
// Returns BootResult::kUpdate if it doesn't.
// Returns BootResult::kRetry if we detect a transient error.
//
// This is extracted to a helper function because it would normally be called
// during CheckStage1, but for the older boot flow (stage0 version 3 and older)
// it is done in CheckStage0 instead. We changed the behaviour so that stage1
// reports its own version after launch, stage0 doesn't report the stage1
// version anymore.
// TODO(b/227977336): This logic can be moved into CheckStage1 after we stop
// supporting stage0 v3.
hps::HPS_impl::BootResult HPS_impl::CheckStage1Version() {
  std::optional<uint16_t> version_low =
      this->device_->ReadReg(HpsReg::kFirmwareVersionLow);
  std::optional<uint16_t> version_high =
      this->device_->ReadReg(HpsReg::kFirmwareVersionHigh);
  if (!version_low || !version_high) {
    // TODO(evanbenn) log a metric
    OnTransientBootFault(FROM_HERE, "ReadReg failure");
    return BootResult::kRetry;
  }
  this->actual_stage1_version_ =
      static_cast<uint32_t>(version_high.value() << 16) | version_low.value();
  if (this->actual_stage1_version_ == this->required_stage1_version_) {
    // Stage 1 is verified
    VLOG(1) << "Stage1 version OK";
    return BootResult::kOk;
  } else {
    // Versions do not match, need to update.
    LOG(INFO) << "Stage1 version mismatch, module: "
              << this->actual_stage1_version_
              << " expected: " << this->required_stage1_version_;
    hps_metrics_->SendHpsTurnOnResult(
        HpsTurnOnResult::kMcuVersionMismatch,
        base::TimeTicks::Now() - this->boot_start_time_);
    return BootResult::kUpdate;
  }
}

// Check stage1 status:
// Check status flags.
// Check stage1 version.
// Check spi verification.
// Return BootResult::kOk if stage1 is running and up-to-date.
// Return BootResult::kUpdate if an update should be sent.
// Return BootResult::kRetry if we detect a transient error.
hps::HPS_impl::BootResult HPS_impl::CheckStage1() {
  if (!CheckMagic()) {
    hps_metrics_->SendHpsTurnOnResult(
        HpsTurnOnResult::kStage1NotStarted,
        base::TimeTicks::Now() - this->boot_start_time_);
    OnTransientBootFault(FROM_HERE, "Timeout waiting for stage1 magic number");
    return BootResult::kRetry;
  }

  std::optional<uint16_t> status = this->device_->ReadReg(HpsReg::kSysStatus);
  if (!status) {
    // TODO(evanbenn) log a metric
    OnTransientBootFault(FROM_HERE, "ReadReg failure");
    return BootResult::kRetry;
  }

  if (status.value() & R2::kFault || !(status.value() & R2::kOK)) {
    // If stage1 is blank/missing/out-of-date we will get one of the errors
    // related to stage1 validation after we tried to launch it.
    // Check for those first.
    std::optional<uint16_t> error = this->device_->ReadReg(HpsReg::kError);
    if (!error) {
      OnTransientBootFault(FROM_HERE, "ReadReg failure");
      return BootResult::kRetry;
    }
    if (error.value() == RError::kStage1NotFound ||
        error.value() == RError::kStage1TooOld ||
        error.value() == RError::kStage1InvalidSignature ||
        error.value() == RError::kMcuFlashEcc) {
      LOG(INFO) << "Stage1 flash not verified: "
                << HpsRegValToString(HpsReg::kError, error.value());
      hps_metrics_->SendHpsTurnOnResult(
          HpsTurnOnResult::kMcuNotVerified,
          base::TimeTicks::Now() - this->boot_start_time_);
      return BootResult::kUpdate;
    }
    // Any other error after launching stage1 is unexpected.
    OnBootFault(FROM_HERE);
  }

  if (!(status.value() & R2::kStage1)) {
    hps_metrics_->SendHpsTurnOnResult(
        HpsTurnOnResult::kStage1NotStarted,
        base::TimeTicks::Now() - this->boot_start_time_);
    if (status.value() & R2::kOneTimeInit) {
      // One-time-init is a special stage1 payload used by hps-factory.
      // If we see it, send an update to get back to the real stage1.
      return BootResult::kUpdate;
    }
    OnTransientBootFault(FROM_HERE, "Stage 1 did not start");
    return BootResult::kRetry;
  }
  VLOG(1) << "Stage 1 OK";

  return this->CheckStage1Version();
}

// Check stage2 status:
// Check status flags.
// Return BootResult::kOk if application is running.
// Return BootResult::kUpdate if an update should be sent.
// Return BootResult::kRetry if we detect a transient error.
hps::HPS_impl::BootResult HPS_impl::CheckApplication() {
  // Poll for kAppl (started) or kSpiNotVer (not started)
  base::ElapsedTimer timer;
  base::TimeDelta elapsed;
  do {
    Sleep(kApplSleep);

    // We measure time to the start of the request, not the end when
    // determining timeouts. If a ReadReg call takes a while because I2C was
    // down when we started the request and we had to wait for the bus to time
    // out, then we don't allow that to put us past our timeout until we've
    // made at least one more request.
    elapsed = timer.Elapsed();

    std::optional<uint16_t> status = this->device_->ReadReg(HpsReg::kSysStatus);
    if (!status) {
      // While launching the application, the MCU temporarily speeds up its
      // clocks, which requires reconfiguring its I2C interface. So occasional
      // errors are nothing to be concerned about. Keep going until we reach
      // the timeout.
      continue;
    }
    if (status.value() & R2::kAppl) {
      VLOG(1) << "Application boot after " << elapsed.InMilliseconds() << "ms";
      hps_metrics_->SendHpsTurnOnResult(
          HpsTurnOnResult::kSuccess,
          base::TimeTicks::Now() - this->boot_start_time_);
      return BootResult::kOk;
    }

    std::optional<uint16_t> error = this->device_->ReadReg(HpsReg::kError);
    if (!error) {
      // As for status check above.
      continue;
    }
    if (error.value() == RError::kSpiFlashNotVerified) {
      VLOG(1) << "SPI verification failed after " << elapsed.InMilliseconds()
              << "ms";
      hps_metrics_->SendHpsTurnOnResult(
          HpsTurnOnResult::kSpiNotVerified,
          base::TimeTicks::Now() - this->boot_start_time_);
      return BootResult::kUpdate;
    } else if (error.value()) {
      OnBootFault(FROM_HERE);
    }
  } while (elapsed < kApplTimeout);

  hps_metrics_->SendHpsTurnOnResult(
      HpsTurnOnResult::kApplNotStarted,
      base::TimeTicks::Now() - this->boot_start_time_);
  OnTransientBootFault(FROM_HERE, "Application did not start");
  return BootResult::kRetry;
}

// Reboot the hardware module.
bool HPS_impl::Reboot() {
  if (wake_lock_)
    ShutDown();
  LOG(INFO) << "Starting HPS device";
  wake_lock_ = device_->CreateWakeLock();

  // On some units, HPS fails to start reliably after powering on. Detect and
  // work around this by toggling the power gpio off and on again one extra
  // time. See b/228917921.
  if (!CheckMagic()) {
    LOG(ERROR) << "Unable to read magic number after powering on, retrying...";
    ShutDown();
    wake_lock_ = device_->CreateWakeLock();
    if (!CheckMagic()) {
      hps_metrics_->SendHpsTurnOnResult(
          HpsTurnOnResult::kPowerOnRecoveryFailed,
          base::TimeTicks::Now() - this->boot_start_time_);
      OnFatalError(FROM_HERE, "HPS device recovery failed");
    } else {
      LOG(INFO) << "HPS device recovered";
      hps_metrics_->SendHpsTurnOnResult(
          HpsTurnOnResult::kPowerOnRecoverySucceeded, base::TimeDelta());
    }
  }

  // If the wake lock isn't really controlling power, send a reset command
  // instead.
  if (!wake_lock_->supports_power_management()) {
    if (!this->device_->WriteReg(HpsReg::kSysCmd, R3::kReset)) {
      OnTransientBootFault(FROM_HERE, "Reboot failed");
      return false;
    }
  }
  return true;
}

bool HPS_impl::ShutDown() {
  DCHECK(wake_lock_);
  LOG(INFO) << "Shutting down HPS device";
  wake_lock_.reset();
  feat_enabled_ = 0;
  Sleep(kPowerOffDelay);
  return true;
}

bool HPS_impl::IsRunning() {
  DCHECK(wake_lock_);
  // Check the application is enabled and running.
  std::optional<uint16_t> status = this->device_->ReadReg(HpsReg::kSysStatus);
  if (!status || !(status.value() & R2::kAppl)) {
    LOG(ERROR) << "Fault: application not running";
    return false;
  }

  // Check for errors.
  std::optional<uint16_t> errors = this->device_->ReadReg(HpsReg::kError);
  if (errors.has_value() && errors.value()) {
    std::string msg =
        "Error " + HpsRegValToString(HpsReg::kError, errors.value());
    // For transient camera errors, try resetting the module (b/266351818).
    if (errors.value() == RError::kCameraImageTimeout &&
        ++transient_error_count_ < kMaxTransientErrors) {
      LOG(ERROR) << "Fault: transient camera error #" << transient_error_count_
                 << ", resetting HPS: " << msg;
      return false;
    }
    OnFatalError(FROM_HERE, msg);
  }
  return true;
}

// Fault bit seen during boot, attempt to dump status information and abort.
// Only call this function in the boot process.
[[noreturn]] void HPS_impl::OnBootFault(const base::Location& location) {
  hps_metrics_->SendHpsTurnOnResult(
      HpsTurnOnResult::kFault, base::TimeTicks::Now() - this->boot_start_time_);
  OnFatalError(location, "Boot fault");
}

[[noreturn]] void HPS_impl::OnFatalError(const base::Location& location,
                                         const std::string& msg) {
  LOG(ERROR) << "Fatal error at " << location.ToString() << ": " << msg;
  LogStateOnError();
  LOG(FATAL) << "Terminating for fatal error at " << location.ToString() << ": "
             << msg;
  abort();
}

void HPS_impl::OnTransientBootFault(const base::Location& location,
                                    const std::string& msg) {
  LOG(WARNING) << "Boot attempt failed with transient error at "
               << location.ToString() << ": " << msg;
  base::TimeDelta suspend_time = GetSystemSuspendTime();
  // If the system got suspended during booting, HPS is now probably in an
  // indeterminate state. In this case, ignore transient errors and try booting
  // again from scratch, hoping we don't get interrupted again.
  if (suspend_time - boot_start_suspend_time_ > kSuspendThreshold) {
    boot_start_suspend_time_ = suspend_time;
    LOG(INFO) << "System suspend detected, retrying boot";
    return;
  }
  LogStateOnError();
  LOG(FATAL) << "Terminating for boot fault at " << location.ToString() << ": "
             << msg;
  abort();
}

void HPS_impl::LogStateOnError() {
  LOG(ERROR) << base::StringPrintf("- Requested feature status: 0x%04x",
                                   feat_enabled_);
  LOG(ERROR) << base::StringPrintf("- Stage1 rootfs version: 0x%08x",
                                   required_stage1_version_);
  LOG(ERROR) << base::StringPrintf("- Stage1 running version: 0x%08x",
                                   actual_stage1_version_);
  LOG(ERROR) << base::StringPrintf("- HW rev: 0x%04x", hw_rev_);
  LOG(ERROR) << base::StringPrintf("- Updates sent: mcu:%d spi:%d",
                                   mcu_update_sent_, spi_update_sent_);
  LOG(ERROR) << base::StringPrintf("- Wake lock: %d", !!wake_lock_);
  LOG(ERROR) << base::StringPrintf("- Transient errors: %d",
                                   transient_error_count_);
  DumpHpsRegisters(*device_,
                   [](const std::string& s) { LOG(ERROR) << "- " << s; });
}

// Send the stage1 MCU flash update.
// Returns if update was sent
void HPS_impl::SendStage1Update() {
  LOG(INFO) << "Updating MCU flash";
  base::ElapsedTimer timer;
  if (this->Download(HpsBank::kMcuFlash, this->mcu_blob_)) {
    hps_metrics_->SendHpsUpdateDuration(HpsBank::kMcuFlash, timer.Elapsed());
  } else {
    hps_metrics_->SendHpsTurnOnResult(
        HpsTurnOnResult::kMcuUpdateFailure,
        base::TimeTicks::Now() - this->boot_start_time_);
    OnFatalError(FROM_HERE, "Failed sending stage1 update");
  }
}

// Send the Application SPI flash update.
// Returns kFail or kUpdate.
void HPS_impl::SendApplicationUpdate() {
  LOG(INFO) << "Updating SPI flash";
  base::ElapsedTimer timer;
  if (this->Download(HpsBank::kSpiFlash, this->fpga_bitstream_) &&
      this->Download(HpsBank::kSocRom, this->fpga_app_image_)) {
    hps_metrics_->SendHpsUpdateDuration(HpsBank::kSpiFlash, timer.Elapsed());
  } else {
    hps_metrics_->SendHpsTurnOnResult(
        HpsTurnOnResult::kSpiUpdateFailure,
        base::TimeTicks::Now() - this->boot_start_time_);
    OnFatalError(FROM_HERE, "Failed sending stage1 update");
  }
}

/*
 * Download data to the bank specified.
 * The HPS/Host I2C Interface Memory Write is used.
 */
bool HPS_impl::Download(hps::HpsBank bank, const base::FilePath& source) {
  DCHECK(wake_lock_);
  uint8_t ibank = static_cast<uint8_t>(bank);
  if (ibank >= kNumBanks) {
    LOG(ERROR) << "Download: Illegal bank: " << static_cast<int>(ibank) << ": "
               << source;
    return -1;
  }
  std::optional<std::vector<uint8_t>> contents = this->DecompressFile(source);
  if (!contents.has_value())
    return false;
  return this->WriteFile(ibank, source, contents.value());
}

std::optional<std::vector<uint8_t>> HPS_impl::DecompressFile(
    const base::FilePath& source) {
  std::string compressed_contents;
  if (!base::ReadFileToString(source, &compressed_contents)) {
    PLOG(ERROR) << "DecompressFile: \"" << source << "\": Reading failed";
    return std::nullopt;
  }

  if (source.FinalExtension() != ".xz") {
    // Assume it's not actually compressed and return its contents as is.
    std::vector<uint8_t> uncompressed(compressed_contents.begin(),
                                      compressed_contents.end());
    return std::make_optional(std::move(uncompressed));
  }

  std::vector<uint8_t> decompressed(2 * 1024 * 1024);  // max 2MB decompressed
  uint64_t memlimit = 20 * 1024 * 1024;  // limit decoder to allocating 20MB
  size_t in_pos = 0;
  size_t out_pos = 0;
  lzma_ret ret = lzma_stream_buffer_decode(
      &memlimit, /* flags */ 0, /* allocator */ nullptr,
      reinterpret_cast<const uint8_t*>(compressed_contents.data()), &in_pos,
      compressed_contents.size(), decompressed.data(), &out_pos,
      decompressed.size());
  if (ret != LZMA_OK) {
    LOG(ERROR) << "DecompressFile: \"" << source
               << "\": Decompressing failed with error " << ret;
    return std::nullopt;
  }
  decompressed.resize(out_pos);
  return std::make_optional(std::move(decompressed));
}

void HPS_impl::SetDownloadObserver(DownloadObserver observer) {
  this->download_observer_ = std::move(observer);
}

/*
 * Write the file to the bank indicated.
 */
bool HPS_impl::WriteFile(uint8_t bank,
                         const base::FilePath& source,
                         const std::vector<uint8_t>& contents) {
  switch (bank) {
    case static_cast<uint8_t>(HpsBank::kMcuFlash):
      if (!this->device_->WriteReg(HpsReg::kSysCmd, R3::kEraseStage1)) {
        LOG(ERROR) << "WriteFile: error erasing bank: "
                   << static_cast<int>(bank);
        return false;
      }
      break;
    case static_cast<uint8_t>(HpsBank::kSpiFlash):
      // Note that this also erases bank 2 (HpsBank::kSocRom)
      // because they are both on the same SPI flash!
      if (!this->device_->WriteReg(HpsReg::kSysCmd, R3::kEraseSpiFlash)) {
        LOG(ERROR) << "WriteFile: error erasing bank: "
                   << static_cast<int>(bank);
        return false;
      }
      break;
    case static_cast<uint8_t>(HpsBank::kSocRom):
      // Assume it was already erased by writing HpsBank::kSpiFlash before this.
      break;
  }
  if (!this->WaitForBankReady(bank)) {
    LOG(ERROR) << "WriteFile: bank " << static_cast<int>(bank)
               << " not ready after erase";
    return false;
  }
  base::ElapsedTimer timer;
  size_t block_size = this->device_->BlockSizeBytes();
  /*
   * Leave room for a 32 bit address at the start of the block to be written.
   * The address is updated for each block to indicate
   * where this block is to be written.
   * The format of the data block is:
   *    4 bytes of address in big endian format
   *    data
   */
  auto buf = std::make_unique<uint8_t[]>(block_size + sizeof(uint32_t));
  // Iterate over the firmware contents in blocks of *block_size* bytes.
  auto block_begin = contents.begin();
  while (block_begin != contents.end()) {
    // The current block ends after *block_size* bytes,
    // or at end of *contents* if there are fewer bytes remaining.
    auto block_end = std::distance(block_begin, contents.end()) >=
                             static_cast<std::ptrdiff_t>(block_size)
                         ? block_begin + block_size
                         : contents.end();
    // The address is just the offset of the current block from the beginning.
    uint32_t address =
        static_cast<uint32_t>(std::distance(contents.begin(), block_begin));
    buf[0] = address >> 24;
    buf[1] = (address >> 16) & 0xff;
    buf[2] = (address >> 8) & 0xff;
    buf[3] = address & 0xff;
    std::copy(block_begin, block_end, &buf[sizeof(uint32_t)]);
    size_t length = std::distance(block_begin, block_end) + sizeof(uint32_t);
    if (!this->device_->Write(I2cMemWrite(bank), &buf[0], length)) {
      LOG(ERROR) << "WriteFile: device write error. bank: "
                 << static_cast<int>(bank);
      return false;
    }
    // Wait for the bank to become ready, indicating that the previous write has
    // finished.
    if (!this->WaitForBankReady(bank)) {
      LOG(ERROR) << "WriteFile: bank " << static_cast<int>(bank)
                 << " not ready after write";
      return false;
    }
    if (download_observer_) {
      download_observer_.Run(source, static_cast<uint32_t>(contents.size()),
                             std::distance(contents.begin(), block_end),
                             timer.Elapsed());
    }
    block_begin = block_end;
  }
  VLOG(1) << "Wrote " << contents.size() << " bytes from " << source << " in "
          << timer.Elapsed().InMilliseconds() << "ms";
  return true;
}

bool HPS_impl::WaitForBankReady(uint8_t bank) {
  base::ElapsedTimer timer;
  do {
    std::optional<uint16_t> result = this->device_->ReadReg(HpsReg::kBankReady);
    if (result && (result.value() & (1 << bank))) {
      return true;
    }
    Sleep(kBankReadySleep);
  } while (timer.Elapsed() < kBankReadyTimeout);
  return false;
}

base::TimeDelta HPS_impl::GetSystemSuspendTime() {
  // Estimates how much time the system has spend in a suspended state since
  // boot. The boot time clock keeps running in suspend state while the
  // monotonic one pauses, so their difference gives an indication on the total
  // time spent suspended. Note that the returned absolute value is mostly
  // meaningless since the clocks likely have different epochs, but differences
  // in measurements taken at different points in time can estimate the time
  // spent suspended during that interval.
  return GetTime(CLOCK_BOOTTIME) - GetTime(CLOCK_MONOTONIC);
}

}  // namespace hps
