// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
 * Device access interface.
 */
#ifndef HPS_DEV_H_
#define HPS_DEV_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include <hps/hps_reg.h>

namespace hps {

class WakeLock {
 public:
  virtual ~WakeLock() = default;
  WakeLock(const WakeLock&) = delete;
  WakeLock& operator=(const WakeLock&) = delete;
  virtual bool supports_power_management() = 0;

 protected:
  WakeLock() = default;
};

class DevInterface {
 public:
  virtual ~DevInterface() {}

  /*
   * Create a new wake lock object. A wake lock must be held while performing
   * read or write operations on this device to ensure the device remains
   * powered up.
   *
   * If the device-specific implementation supports power management, the
   * hardware will remain powered on as long as at least one wake lock is
   * active. Otherwise this function is a no-op.
   */
  virtual std::unique_ptr<WakeLock> CreateWakeLock();

  /*
   * Returns true on successful read, false on error.
   * In the event of an error, the contents may have been modified.
   */
  [[nodiscard]] virtual bool Read(uint8_t cmd, uint8_t* data, size_t len);

  /*
   * Write the data to the device.
   * Returns true on successful write, false on error.
   */
  [[nodiscard]] virtual bool Write(uint8_t cmd,
                                   const uint8_t* data,
                                   size_t len);

  /*
   * Read 1 register.
   * Returns value read, or -1 for error.
   */
  [[nodiscard]] virtual std::optional<uint16_t> ReadReg(HpsReg r);

  /*
   * Read a register which holds a string.
   * Returns value read, or nullopt for error.
   */
  [[nodiscard]] virtual std::optional<std::string> ReadStringReg(HpsReg r,
                                                                 size_t len);

  /*
   * Write 1 register.
   * Returns false on failure.
   */
  [[nodiscard]] virtual bool WriteReg(HpsReg r, uint16_t data);

  /*
   * Return the maximum download block size (in bytes).
   * This value is the actual data to be written, not including the
   * write command byte or the 4 byte address header.
   * This must be a power of two.
   */
  virtual size_t BlockSizeBytes();

 private:
  /*
   * Device specific implementations of the Read/Write methods,
   * with the same contract.
   */
  virtual bool ReadDevice(uint8_t cmd, uint8_t* data, size_t len) = 0;
  virtual bool WriteDevice(uint8_t cmd, const uint8_t* data, size_t len) = 0;
};

}  // namespace hps

#endif  // HPS_DEV_H_
