// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
 * MCP2221A device interface layer.
 */
#include "hps/hal/mcp.h"

#include <memory>
#include <utility>

#include <libusb-1.0/libusb.h>
#include <stdlib.h>

#include <base/check.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <base/threading/thread.h>
#include <base/time/time.h>
#include <base/timer/elapsed_timer.h>

namespace {

// USB parameters.
static const uint16_t kUsbVendorIdMCP2221 = 0x04d8;
static const uint16_t kUsbDeviceIdMCP2221 = 0x00dd;
static const int kUsbInterfaceNumber = 2;
static const uint8_t kWriteEndpoint = 0x03;  // host to device
static const uint8_t kReadEndpoint = 0x83;   // device to host

static const int kTimeout = 1000;      // Timeout in milliseconds.
static const int kRetries = 50;        // Max retries.

static constexpr base::TimeDelta kDelay =
    base::Milliseconds(10);  // Delay between retries.
static constexpr base::TimeDelta kReadSleep = base::Milliseconds(1);
static constexpr base::TimeDelta kReadTimeout = base::Milliseconds(1000);

/*
 * Calculate write block size.
 * The I2C header is 4 bytes.
 * 1 byte is reserved for the I2C cmd byte, 4 for the 32 bit address.
 * The value should be a power of 2
 * 48 == ((hps::kMcpTransferSize - 4 - sizeof(uint32_t) - 1) / 8) * 8;
 */
static constexpr size_t kBlockSize = 32;

// Command byte to send to MCP2221
enum : uint8_t {
  kCmdStatus = 0x10,
  kCmdReadData = 0x40,
  kCmdGetGpio = 0x51,
  kCmdSetSram = 0x60,
  kCmdWriteData = 0x90,
  kCmdReadRepeatStart = 0x93,
  kCmdWriteNoStop = 0x94,
};

/*
 * Convert status to error string.
 */
static inline const char* errString(int status) {
  return libusb_strerror(static_cast<libusb_error>(status));
}
/*
 * Clock divider uses 12MHz clock as base, divided by target
 * bus speed in Hz, offset by 2.
 */
static inline uint8_t ClockDivider(uint32_t speed_khz) {
  DCHECK_GE(speed_khz, 50u);
  DCHECK_LE(speed_khz, 1000u);
  return static_cast<uint8_t>((12 * 1000) / speed_khz - 2);
}

}  // namespace

namespace hps {

Mcp::~Mcp() {
  Close();
}

/*
 * Open and initialise the MCP2221A device.
 * Scan the available USB devices until the correct VID/PID is found,
 * and then open that device.
 */
bool Mcp::Init(uint32_t speed_khz) {
  if (speed_khz > 1000 || speed_khz < 50) {
    LOG(ERROR) << "I2C bus speed must be > 50KHz and < 1000KHz";
    return false;
  }
  this->div_ = ClockDivider(speed_khz);
  int status = libusb_init(&this->context_);
  if (status != 0) {
    this->context_ = nullptr;
    LOG(ERROR) << "libusb_init: " << errString(status);
    return false;
  }
  // Get list of devices.
  libusb_device** list;
  ssize_t count = libusb_get_device_list(this->context_, &list);
  bool ret = false;
  for (int i = 0; i < count; i++) {
    libusb_device_descriptor desc;
    status = libusb_get_device_descriptor(list[i], &desc);
    if (status != 0) {
      LOG(ERROR) << "get_device_descriptor: " << errString(status);
      break;
    }
    if (desc.idVendor == kUsbVendorIdMCP2221 &&
        desc.idProduct == kUsbDeviceIdMCP2221) {
      // Found the correct device.
      status = libusb_open(list[i], &this->handle_);
      if (status != 0) {
        LOG(ERROR) << "libusb_open: " << errString(status);
        break;
      }
      status = libusb_claim_interface(this->handle_, kUsbInterfaceNumber);
      if (status != 0) {
        LOG(ERROR) << "claim interface: " << errString(status);
        // Close the handle here, since Close() assumes that the
        // interface has been claimed.
        libusb_close(this->handle_);
        this->handle_ = nullptr;
        break;
      }
      libusb_device* dev = libusb_get_device(this->handle_);
      /*
       * Read the device status to ensure it is reachable, and to
       * retrieve the hardware and firmware revision.
       */
      this->Clear();
      this->out_[0] = kCmdStatus;
      if (!this->Cmd()) {
        break;
      }
      LOG(INFO) << base::StringPrintf(
          "MCP2221 at bus %d port %d H/W rev %c.%c f/w %c.%c",
          libusb_get_bus_number(dev), libusb_get_port_number(dev),
          this->in_[46], this->in_[47], this->in_[48], this->in_[49]);

      /* Set GPIO0 high to enable the level converter */
      this->Clear();
      this->out_[0] = kCmdSetSram;
      /* alter GP settings */
      /* The old datasheet says this must be 1, 2020 datasheet says (1<<7). */
      this->out_[7] = BIT(7);
      /* GP0 settings: GPIO mode, output, set high */
      this->out_[8] = BIT(4);
      if (!this->Cmd() || this->in_[1] != 0) {
        LOG(INFO) << base::StringPrintf("MCP2221A SetSram failure 0x%x 0x%x",
                                        this->in_[0], this->in_[1]);
        break;
      }

      /* Check the GPIO0 setting */
      this->Clear();
      this->out_[0] = kCmdGetGpio;
      if (!this->Cmd() || this->in_[1] != 0 || this->in_[2] != 1 ||
          this->in_[3] != 0) {
        LOG(INFO) << base::StringPrintf("MCP2221A Bad GPIO 0x%x 0x%x 0x%x",
                                        this->in_[0], this->in_[2],
                                        this->in_[3]);
        break;
      }

      ret = true;
      break;
    }
  }
  libusb_free_device_list(list, 1);
  if (!ret) {
    LOG(ERROR) << "Failed to open MCP2221";
    this->Close();
  }
  return ret;
}

void Mcp::Close() {
  // If handle set, interface is claimed.
  if (this->handle_ != nullptr) {
    libusb_release_interface(this->handle_, kUsbInterfaceNumber);
    libusb_close(this->handle_);
    this->handle_ = nullptr;
  }
  if (this->context_ != nullptr) {
    libusb_exit(this->context_);
    this->context_ = nullptr;
  }
}

bool Mcp::ReadDevice(uint8_t cmd, uint8_t* data, size_t len) {
  if (!this->PrepareBus()) {
    return false;
  }
  // Send a I2C Write Data No STOP with the cmd as data.
  this->Clear();
  this->out_[0] = kCmdWriteNoStop;
  this->out_[1] = 1;  // LSB transfer length
  this->out_[2] = 0;  // MSB transfer length
  this->out_[3] = this->address_;
  this->out_[4] = cmd;
  if (!this->Cmd()) {
    LOG(ERROR) << "Read (cmd phase) failed";
    return false;
  }
  if (this->in_[1] != 0) {
    // Should retry here.
    LOG(ERROR) << "Read (busy) failed";
    return false;
  }
  this->Clear();
  this->out_[0] = kCmdReadRepeatStart;
  this->out_[1] = len & 0xff;          // LSB transfer length
  this->out_[2] = (len >> 8) & 0xff;   // MSB transfer length
  this->out_[3] = this->address_ | 1;  // For read.
  if (!this->Cmd()) {
    LOG(ERROR) << "Read (read phase) failed";
    return false;
  }
  if (this->in_[1] != 0) {
    // Should retry here.
    LOG(ERROR) << "Read (read busy) failed";
    return false;
  }
  size_t len_remaining = len;
  uint8_t* data_remaining = data;
  this->Clear();
  base::ElapsedTimer timer;
  do {
    this->out_[0] = kCmdReadData;
    if (!this->Cmd()) {
      LOG(ERROR) << "Read (read data) failed";
      return false;
    }
    if (this->in_[1] == 0) {
      if (this->in_[3] == 127) {
        LOG(ERROR) << "Read (count error) failed";
        return false;
      }
      size_t sz = this->in_[3];
      if (sz > len_remaining) {
        LOG(ERROR) << base::StringPrintf("Read size error (%zu)", sz);
        return false;
      }
      memcpy(data_remaining, &this->in_[4], sz);
      data_remaining += sz;
      len_remaining -= sz;
      if (len_remaining) {
        continue;
      } else {
        return true;
      }
    }
    base::PlatformThread::Sleep(kReadSleep);
  } while (timer.Elapsed() < kReadTimeout);
  LOG(ERROR) << "Read (retries exceeded) failed: " << timer.Elapsed();
  return false;
}

bool Mcp::WriteDevice(uint8_t cmd, const uint8_t* data, size_t len) {
  if (len > (kMcpTransferSize - 5)) {
    LOG(ERROR) << base::StringPrintf("Write req too long (%zu)", len);
    return false;
  }
  if (!this->PrepareBus()) {
    return false;
  }
  // Send I2C Write Data
  this->Clear();
  this->out_[0] = kCmdWriteData;
  this->out_[1] = (len + 1) & 0xff;  // LSB transfer length
  this->out_[2] = 0;                 // MSB transfer length
  this->out_[3] = this->address_;
  this->out_[4] = cmd;
  memcpy(&this->out_[5], data, len);
  if (!this->Cmd()) {
    LOG(ERROR) << "Write (cmd phase) failed";
    return false;
  }
  // Wait for write to complete.
  for (int i = 0; i < kRetries; i++) {
    this->Clear();
    this->out_[0] = kCmdStatus;
    if (!this->Cmd()) {
      LOG(ERROR) << "Write (wait for complete) failed";
      return false;
    }
    if (this->in_[8] == 0) {  // bus is idle.
      return true;
    }
    base::PlatformThread::Sleep(kDelay);
  }
  LOG(ERROR) << "Write (retries exceeded) failed";
  return false;
}

/*
 * Return max block size for download.
 */
size_t Mcp::BlockSizeBytes() {
  return kBlockSize;
}

// Ensure the I2C bus is ready. Returns true if bus is clear and ready.
bool Mcp::PrepareBus() {
  this->Clear();
  for (int i = 0; i < kRetries; i++) {
    // Send a status/setup command.
    this->out_[0] = kCmdStatus;
    // If the bus is not ready, send a cancel transaction subcommand
    // on the first retry. This will clear any pending transaction
    // and reset the I2C controller.
    this->out_[2] = (i == 1) ? 0x10 : 0;  // No cancel on first try.
    this->out_[3] = 0x20;                 // Set clock divider.
    this->out_[4] = this->div_;
    if (!this->Cmd()) {
      LOG(ERROR) << "PrepareBus CMD failed";
      return false;
    }
    if (this->in_[1] != 0x00) {
      LOG(ERROR) << base::StringPrintf("Cmd failed, status: 0x%x",
                                       this->in_[1]);
      return false;
    }
    if (this->in_[3] == 0x20) {  // Set speed succeeded.
      return true;
    }
    base::PlatformThread::Sleep(kDelay);
  }
  LOG(ERROR) << "PrepareBus retries exceeded";
  return false;
}

// Send the USB output data block and read the response.
bool Mcp::Cmd() {
  CHECK(this->handle_);
  int transferred = 0;
  int status =
      libusb_interrupt_transfer(this->handle_, kWriteEndpoint, this->out_,
                                kMcpTransferSize, &transferred, kTimeout);
  if (status != 0) {
    LOG(ERROR) << "Send (TX): " << errString(status);
    return false;
  }
  if (transferred != kMcpTransferSize) {
    LOG(WARNING) << "Short TX: " << transferred;
  }
  // Now read the response.
  transferred = 0;
  status = libusb_interrupt_transfer(this->handle_, kReadEndpoint, this->in_,
                                     kMcpTransferSize, &transferred, kTimeout);
  if (status != 0) {
    LOG(ERROR) << "Send (RX): " << errString(status);
    return false;
  }
  if (transferred != kMcpTransferSize) {
    LOG(WARNING) << "Short RX: " << transferred;
  }
  VLOG(1) << base::StringPrintf(
      "Out: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x", this->out_[0],
      this->out_[1], this->out_[2], this->out_[3], this->out_[4], this->out_[5],
      this->out_[6], this->out_[7], this->out_[8], this->out_[9]);
  VLOG(1) << base::StringPrintf(
      " In: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x", this->in_[0],
      this->in_[1], this->in_[2], this->in_[3], this->in_[4], this->in_[5],
      this->in_[6], this->in_[7], this->in_[8], this->in_[9]);
  return true;
}

// Clear the input and output buffers.
void Mcp::Clear() {
  memset(this->in_, 0, sizeof(this->in_));
  memset(this->out_, 0, sizeof(this->out_));
}

// Static factory method.
std::unique_ptr<DevInterface> Mcp::Create(uint8_t address, uint32_t speed_khz) {
  // Use new so that private constructor can be accessed.
  auto dev = std::unique_ptr<Mcp>(new Mcp(address));
  CHECK(dev->Init(speed_khz));
  return std::unique_ptr<DevInterface>(std::move(dev));
}

}  // namespace hps
