// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HPS_HPS_H_
#define HPS_HPS_H_

#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <base/time/time.h>

#include "hps/hps_reg.h"

namespace hps {

class DevInterface;

class HPS {
 public:
  virtual ~HPS() = default;

  // Set the application version and firmware.
  virtual void Init(uint32_t stage1_version,
                    const base::FilePath& mcu,
                    const base::FilePath& fpga_bitstream,
                    const base::FilePath& fpga_app_image) = 0;

  //
  // Boot the module, returns true if the module is working and ready.
  // Requires that the MCU and SPI flash blobs have been
  // set via Init().
  //
  virtual void Boot() = 0;

  // Shut down the module. If the module is needed again, it must be
  // reinitialized with Boot() before calling other operations.
  virtual bool ShutDown() = 0;

  //
  // Check if the module is running normally and ready for feature control and
  // detection.
  //
  virtual bool IsRunning() = 0;

  //
  // Enable the selected feature, return false if the
  // request fails e.g if the module is not ready.
  // The feature is represented as a feature index
  // starting from 0, with a current maximum of 15.
  //
  virtual bool Enable(uint8_t feature) = 0;

  //
  // Disable the selected feature.
  //
  virtual bool Disable(uint8_t feature) = 0;

  //
  // Return the latest result for the feature selected,
  // where the feature ranges from 0 to 15, corresponding to
  // the features selected in the Enable method above.
  //
  virtual FeatureResult Result(int feature) = 0;

  //
  // Return the underlying access device for the module.
  //
  virtual DevInterface* Device() = 0;

  //
  // Download a file to the bank indicated.
  // Per the HPS/Host I2C Interface, the bank
  // must be between 0-63 inclusive.
  // Returns true on success, false on failure.
  //
  virtual bool Download(hps::HpsBank bank, const base::FilePath& source) = 0;

  //
  // Set a callback to be notified of incremental download progress. The
  // callback will be called periodically during download operations.
  //
  using DownloadObserver =
      base::RepeatingCallback<void(const base::FilePath& /*file_path*/,
                                   uint64_t /*total_bytes*/,
                                   uint64_t /*downloaded_bytes*/,
                                   base::TimeDelta /*elapsed_time*/)>;
  virtual void SetDownloadObserver(DownloadObserver) = 0;
};

}  // namespace hps

#endif  // HPS_HPS_H_
