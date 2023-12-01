// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
 * I2C device handler.
 */
#ifndef HPS_HAL_I2C_H_
#define HPS_HAL_I2C_H_

#include <memory>

#include <stdint.h>
#include <string>

#include <base/files/file_path.h>

#include "hps/dev.h"

struct i2c_msg;

namespace hps {

class I2CDev : public DevInterface {
 public:
  ~I2CDev() override {}
  int Open();
  bool ReadDevice(uint8_t cmd, uint8_t* data, size_t len) override;
  bool WriteDevice(uint8_t cmd, const uint8_t* data, size_t len) override;
  std::unique_ptr<WakeLock> CreateWakeLock() override;
  static std::unique_ptr<DevInterface> Create(const std::string& bus,
                                              uint8_t address,
                                              const std::string& power_control);

 private:
  I2CDev(const std::string& bus,
         uint8_t address,
         const base::FilePath& power_control);
  bool Ioc(struct i2c_msg* msg, size_t count);
  const std::string bus_;
  base::FilePath power_control_;
  uint8_t address_;
  int fd_;
};

}  // namespace hps

#endif  // HPS_HAL_I2C_H_
