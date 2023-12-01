// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
 * I2C device handler.
 */
#include "hps/hal/i2c.h"

#include <utility>
#include <vector>

#include <fcntl.h>
#include <stdint.h>

#include <linux/i2c.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/numerics/safe_conversions.h>

namespace hps {
namespace {

/*
 * Holds a file handle to the HPS device, which causes the kernel module
 * to keep the sensor powered as long as the file handle exists.
 *
 * If the HPS kernel driver isn't loaded or the device node doesn't exist, we
 * assume the hardware is always powered on and disable power management in
 * hpsd.
 */
class WakeLockImpl : public WakeLock {
 public:
  explicit WakeLockImpl(const base::FilePath& power_control)
      : power_file_(power_control,
                    base::File::FLAG_OPEN | base::File::FLAG_READ |
                        base::File::FLAG_WRITE) {
    if (!power_file_.IsValid())
      PLOG(FATAL) << "Unable to create wake lock: \"" << power_control << "\"";
  }
  ~WakeLockImpl() override = default;
  bool supports_power_management() override { return true; }

 private:
  base::File power_file_;
};

}  // namespace

I2CDev::I2CDev(const std::string& bus,
               uint8_t addr,
               const base::FilePath& power_control)
    : bus_(bus), power_control_(power_control), address_(addr), fd_(-1) {}

int I2CDev::Open() {
  if (this->bus_.empty()) {
    LOG(ERROR) << "Empty i2c path: \"" << this->bus_ << "\"";
    return -1;
  }
  if (!power_control_.empty() && !base::PathExists(power_control_)) {
    LOG(WARNING) << "Bad power control file, disabling power management: \""
                 << power_control_ << "\"";
    power_control_.clear();
  }
  this->fd_ = open(this->bus_.c_str(), O_RDWR);
  if (this->fd_ < 0) {
    PLOG(ERROR) << "Cannot open: \"" << this->bus_ << "\"";
  }
  return this->fd_;
}

bool I2CDev::ReadDevice(uint8_t cmd, uint8_t* data, size_t len) {
  struct i2c_msg m[2];

  m[0].addr = this->address_;
  m[0].flags = 0;
  m[0].len = sizeof(cmd);
  m[0].buf = &cmd;
  m[1].addr = this->address_;
  m[1].flags = I2C_M_RD;
  m[1].len = base::checked_cast<uint16_t>(len);
  m[1].buf = data;
  return this->Ioc(m, sizeof(m) / sizeof(m[0]));
}

bool I2CDev::WriteDevice(uint8_t cmd, const uint8_t* data, size_t len) {
  struct i2c_msg m[1];
  std::vector<uint8_t> buffer;
  buffer.reserve(len + 1);
  buffer.push_back(cmd);
  buffer.insert(buffer.end(), data, data + len);

  m[0].addr = this->address_;
  m[0].flags = I2C_M_STOP;
  m[0].len = base::checked_cast<uint16_t>(buffer.size());
  m[0].buf = buffer.data();
  return this->Ioc(m, sizeof(m) / sizeof(m[0]));
}

bool I2CDev::Ioc(struct i2c_msg* msg, size_t count) {
  struct i2c_rdwr_ioctl_data ioblk;

  ioblk.msgs = msg;
  ioblk.nmsgs = static_cast<uint32_t>(count);
  int ret = ioctl(this->fd_, I2C_RDWR, &ioblk);
  if (ret < 0) {
    VPLOG(3) << "i2c read/write failed";
  }
  return ret != -1;
}

std::unique_ptr<WakeLock> I2CDev::CreateWakeLock() {
  if (!power_control_.empty())
    return std::make_unique<WakeLockImpl>(power_control_);
  return DevInterface::CreateWakeLock();
}

// Static factory method.
std::unique_ptr<DevInterface> I2CDev::Create(const std::string& bus,
                                             uint8_t addr,
                                             const std::string& power_control) {
  // Use new so that private constructor can be accessed.
  auto i2c_dev = std::unique_ptr<I2CDev>(
      new I2CDev(bus, addr, base::FilePath(power_control)));
  CHECK_GE(i2c_dev->Open(), 0);
  return std::unique_ptr<DevInterface>(std::move(i2c_dev));
}

}  // namespace hps
