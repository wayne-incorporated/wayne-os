// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
 * Implementation of the HPS interface.
 */
#ifndef HPS_HPS_IMPL_H_
#define HPS_HPS_IMPL_H_

#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/threading/thread.h>

#include "hps/dev.h"
#include "hps/hps.h"
#include "hps/hps_metrics.h"
#include "hps/hps_reg.h"

namespace hps {

class HPS_impl : public HPS {
 public:
  friend class HPSTestButUsingAMock;
  explicit HPS_impl(std::unique_ptr<DevInterface> dev)
      : HPS_impl(std::move(dev), std::make_unique<HpsMetrics>()) {}
  explicit HPS_impl(std::unique_ptr<DevInterface> dev,
                    std::unique_ptr<HpsMetricsInterface> metrics)
      : device_(std::move(dev)),
        wake_lock_(device_->CreateWakeLock()),  // Power on by default.
        hps_metrics_(std::move(metrics)),
        hw_rev_(0),
        feat_enabled_(0) {}

  // Methods for HPS
  void Init(uint32_t stage1_version,
            const base::FilePath& mcu,
            const base::FilePath& fpga_bitstream,
            const base::FilePath& fpga_app_image) override;
  void Boot() override;
  bool ShutDown() override;
  bool IsRunning() override;
  bool Enable(uint8_t feature) override;
  bool Disable(uint8_t feature) override;
  FeatureResult Result(int feature) override;
  DevInterface* Device() override { return this->device_.get(); }
  bool Download(hps::HpsBank bank, const base::FilePath& source) override;
  void SetDownloadObserver(DownloadObserver) override;

 private:
  enum class BootResult {
    kOk,
    kUpdate,
    kRetry,
  };

  // These are virtual to allow unit tests to override.
  virtual void Sleep(base::TimeDelta duration) {
    base::PlatformThread::Sleep(duration);
  }
  virtual base::TimeDelta GetSystemSuspendTime();

  BootResult TryBoot();
  bool CheckMagic();
  BootResult CheckStage0();
  BootResult CheckStage1Version();
  BootResult CheckStage1();
  BootResult CheckApplication();
  bool Reboot();

  [[noreturn]] void OnBootFault(const base::Location&);
  [[noreturn]] void OnFatalError(const base::Location&, const std::string& msg);
  void OnTransientBootFault(const base::Location&, const std::string& msg);
  void LogStateOnError();

  bool WaitForBankReady(uint8_t bank);
  void SendStage1Update();
  void SendApplicationUpdate();
  std::optional<std::vector<uint8_t>> DecompressFile(
      const base::FilePath& source);
  bool WriteFile(uint8_t bank,
                 const base::FilePath& source,
                 const std::vector<uint8_t>& contents);
  std::unique_ptr<DevInterface> device_;
  base::TimeTicks boot_start_time_;
  base::TimeDelta boot_start_suspend_time_;
  std::unique_ptr<WakeLock> wake_lock_;
  std::unique_ptr<HpsMetricsInterface> hps_metrics_;
  uint16_t hw_rev_;
  uint32_t required_stage1_version_ = 0;
  uint32_t actual_stage1_version_ = 0;
  bool mcu_update_sent_ = false;
  bool spi_update_sent_ = false;
  uint16_t feat_enabled_;
  int transient_error_count_ = 0;
  base::FilePath mcu_blob_;
  base::FilePath fpga_bitstream_;
  base::FilePath fpga_app_image_;
  DownloadObserver download_observer_{};
};

}  // namespace hps

#endif  // HPS_HPS_IMPL_H_
