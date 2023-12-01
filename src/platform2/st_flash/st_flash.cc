// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// This is a implementation of IAP firmware updater for STM32-based touchpads.

#include <cstdio>
#include <iomanip>
#include <map>
#include <string>
#include <vector>

#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <unistd.h>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <base/command_line.h>
#include <base/files/file_util.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/flag_helper.h>

#define GPIO_SYS "/sys/class/gpio/"
#define PULSE_WIDTH 100000  // 100ms reset pulse width, we need at least 300ns.

constexpr int kMaxI2CDevicePathLen = 150;

// Per-board specific configurations.
struct BoardConfig {
  uint8_t i2cBusMin;
  uint8_t i2cBusMax;
  uint8_t i2cSlaveAddress;
  uint32_t flash_size;
  uint32_t flash_address;
  uint32_t fwInfoAddress;
  int32_t bootGPIO;
  int32_t resetGPIO;
};

// Board specific configurations.
static std::map<std::string, struct BoardConfig> boardConfigs = {
    {
        "eve",
        {
            .i2cBusMin = 7,
            .i2cBusMax = 8,
            .i2cSlaveAddress = 0x46,
            .flash_size = 512 * 1024,
            .flash_address = 0x08000000,
            .fwInfoAddress = 0x80001c4,
            .bootGPIO = 432,
            .resetGPIO = 433,
        },
    },
};

// Global config instance.
static struct BoardConfig config;

enum StatusCode {
  ACK = 0x79,
  NACK = 0x1f,
  BUSY = 0x76,
};

class IAPFirmwareUpdater {
 public:
  IAPFirmwareUpdater(uint8_t i2cBusMin,
                     uint8_t u2cBusMax,
                     uint8_t slaveAddress);

  void Flash(uint32_t address, std::string path, bool verify);
  void ReadFirmware(std::string filename);
  void GetFirmwareVersion();
  bool EnterBootloader();
  void LeaveBootLoader();

 private:
  int i2c_fd_;

  // High level functions.
  void WriteFlash(uint32_t address, std::vector<uint8_t> data);
  std::vector<uint8_t> ReadFlash(uint32_t address, uint32_t length);

  // IAP I2C command wrapper functions.
  bool PollForAck(uint32_t timeoutMs = 5000);
  uint8_t GetVersion();
  int GetId();
  void Erase();
  bool WriteFlashChunk(uint32_t address, uint8_t length, uint8_t* data);
  bool ReadFlashChunk(uint32_t address, uint8_t length, uint8_t* data);

  // Helper functions.
  std::vector<uint8_t> LoadFirmware(std::string path);
  bool WriteCommand(uint8_t command);
  uint8_t ReadOneByte();

  bool WriteToFile(std::string path, std::string value);
};

IAPFirmwareUpdater::IAPFirmwareUpdater(uint8_t i2cBusMin,
                                       uint8_t i2cBusMax,
                                       uint8_t slaveAddress) {
  char dev_path[kMaxI2CDevicePathLen];

  for (uint8_t i = i2cBusMax; i >= i2cBusMin; i--) {
    snprintf(dev_path, kMaxI2CDevicePathLen, "/dev/i2c-%d", i);
    LOG(INFO) << "Attempting to probe <" << dev_path << "> for a touchpad";
    i2c_fd_ = open(dev_path, O_RDWR);
    if (i2c_fd_ < 0) {
      PLOG(INFO) << "Failed to open device";
      continue;
    } else {
      LOG(INFO) << "Successfully opened device, attempting to communicate";
    }

    if (ioctl(i2c_fd_, I2C_SLAVE_FORCE, slaveAddress)) {
      PLOG(INFO) << "Failed to set slave address 0x" << std::hex
                 << static_cast<int>(slaveAddress);
      close(i2c_fd_);
      continue;
    }

    if (!EnterBootloader()) {
      close(i2c_fd_);
    } else {
      LOG(INFO) << "Successfully entered bootloader mode, this is the one!";
      return;
    }
  }
}

bool IAPFirmwareUpdater::PollForAck(uint32_t timeoutMs) {
  struct timespec delay = {.tv_sec = 0, .tv_nsec = 250000000};
  uint8_t byte;
  uint32_t elapseMs = 0;
  struct timeval start, current;
  gettimeofday(&start, NULL);

  while (true) {
    switch ((byte = ReadOneByte())) {
      case ACK:
        return true;
      case NACK:
        return false;
      case BUSY:
        nanosleep(&delay, NULL);
        break;
      default:
        LOG(FATAL) << "PollForAck: unexpected byte 0x" << std::hex
                   << static_cast<int>(byte);
    }

    gettimeofday(&current, NULL);
    elapseMs = ((current.tv_sec - start.tv_sec) * 1000 +
                (current.tv_usec - start.tv_usec) / 1000);
    if (elapseMs > timeoutMs) {
      LOG(ERROR) << "PollForAck: timed out waiting for ACK";
      return false;
    }
  }
}

void IAPFirmwareUpdater::Flash(uint32_t address,
                               std::string path,
                               bool verify) {
  int id = GetId();
  LOG(INFO) << "BootLoader version: 0x" << std::hex
            << static_cast<int>(GetVersion());
  LOG(INFO) << "Chip ID: 0x" << std::hex << id;

  // Begin flashing
  std::vector<uint8_t> firmware = LoadFirmware(path);
  Erase();
  WriteFlash(address, firmware);
  std::vector<uint8_t> readFirmware = ReadFlash(address, firmware.size());

  if (verify) {
    LOG(INFO) << "Verifing firmware ...";
    for (unsigned i = 0; i < firmware.size(); i++) {
      if (firmware[i] != readFirmware[i]) {
        LOG(FATAL) << "Verification failed at 0x" << std::setfill('0')
                   << std::setw(8) << address + i;
      }
    }
    LOG(INFO) << "Firmware verified.";
  }

  LeaveBootLoader();
}

void IAPFirmwareUpdater::GetFirmwareVersion() {
  std::vector<uint8_t> version_bytes(4, 0);
  ReadFlashChunk(config.fwInfoAddress, version_bytes.size(),
                 version_bytes.data());
  uint32_t version = *reinterpret_cast<uint32_t*>(version_bytes.data());
  printf("0x%x\n", version);

  LeaveBootLoader();
}

void IAPFirmwareUpdater::ReadFirmware(std::string filename) {
  std::vector<uint8_t> firmware =
      ReadFlash(config.flash_address, config.flash_size);
  WriteToFile(filename, std::string(firmware.begin(), firmware.end()));
  LOG(INFO) << "Firmware saved to " << filename;

  LeaveBootLoader();
}

bool IAPFirmwareUpdater::EnterBootloader() {
  // Bootloader (IAP mode) can be entered by first asserting the BOOT pin
  // then toggle the reset pin.
  const std::string bootGPIO = base::NumberToString(config.bootGPIO);
  const std::string resetGPIO = base::NumberToString(config.resetGPIO);

  CHECK(WriteToFile(GPIO_SYS "export", bootGPIO));
  CHECK(WriteToFile(GPIO_SYS "export", resetGPIO));
  CHECK(WriteToFile(GPIO_SYS "gpio" + bootGPIO + "/direction", "out"));
  CHECK(WriteToFile(GPIO_SYS "gpio" + resetGPIO + "/direction", "out"));
  CHECK(WriteToFile(GPIO_SYS "gpio" + bootGPIO + "/value", "1"));
  CHECK(WriteToFile(GPIO_SYS "gpio" + resetGPIO + "/value", "1"));
  usleep(PULSE_WIDTH);
  CHECK(WriteToFile(GPIO_SYS "gpio" + resetGPIO + "/value", "0"));
  usleep(PULSE_WIDTH);
  CHECK(WriteToFile(GPIO_SYS "gpio" + bootGPIO + "/value", "0"));
  CHECK(WriteToFile(GPIO_SYS "unexport", bootGPIO));
  CHECK(WriteToFile(GPIO_SYS "unexport", resetGPIO));

  int id = GetId();
  if (id == -1) {
    LOG(INFO) << "Failed to enter bootloader mode.";
    return false;
  }
  return true;
}

void IAPFirmwareUpdater::LeaveBootLoader() {
  const std::string bootGPIO = base::NumberToString(config.bootGPIO);
  const std::string resetGPIO = base::NumberToString(config.resetGPIO);

  CHECK(WriteToFile(GPIO_SYS "export", bootGPIO));
  CHECK(WriteToFile(GPIO_SYS "export", resetGPIO));
  CHECK(WriteToFile(GPIO_SYS "gpio" + bootGPIO + "/direction", "out"));
  CHECK(WriteToFile(GPIO_SYS "gpio" + resetGPIO + "/direction", "out"));
  CHECK(WriteToFile(GPIO_SYS "gpio" + bootGPIO + "/value", "0"));
  CHECK(WriteToFile(GPIO_SYS "gpio" + resetGPIO + "/value", "1"));
  usleep(PULSE_WIDTH);
  CHECK(WriteToFile(GPIO_SYS "gpio" + resetGPIO + "/value", "0"));
  CHECK(WriteToFile(GPIO_SYS "unexport", bootGPIO));
  CHECK(WriteToFile(GPIO_SYS "unexport", resetGPIO));
}

void IAPFirmwareUpdater::WriteFlash(uint32_t address,
                                    std::vector<uint8_t> data) {
  const uint32_t chunkSize = 200;
  uint32_t length = data.size();
  uint32_t sent = 0, to_send = 0;
  uint8_t* buffer = data.data();

  LOG(INFO) << "Writing flash ";
  while (sent < length) {
    printf(".");
    fflush(stdout);
    to_send = std::min(chunkSize, length - sent);
    if (!WriteFlashChunk(address + sent, to_send, buffer + sent)) {
      LOG(FATAL) << "WriteFlashChunk failed at 0x" << std::hex
                 << std::setfill('0') << std::setw(8) << sent;
    }
    sent += to_send;
  }
  printf("\n");
}

std::vector<uint8_t> IAPFirmwareUpdater::ReadFlash(uint32_t address,
                                                   uint32_t length) {
  const uint32_t chunkSize = 200;
  std::vector<uint8_t> data(length, 0);
  uint8_t* buffer = data.data();
  uint32_t read = 0, to_read = 0;

  LOG(INFO) << "Reading flash ";
  while (read < length) {
    printf(".");
    fflush(stdout);
    to_read = std::min(chunkSize, length - read);
    if (!ReadFlashChunk(address + read, to_read, buffer + read)) {
      LOG(FATAL) << "ReadFlashChunk failed at 0x" << std::hex
                 << std::setfill('0') << std::setw(8) << read;
    }
    read += to_read;
  }
  printf("\n");
  return data;
}

uint8_t IAPFirmwareUpdater::GetVersion() {
  CHECK(WriteCommand(0x01));
  CHECK(PollForAck());
  uint8_t version = ReadOneByte();
  CHECK(PollForAck());
  return version;
}

int IAPFirmwareUpdater::GetId() {
  uint8_t idBuf[3];
  if (!WriteCommand(0x02)) {
    return -1;
  }
  if (!PollForAck()) {
    return -1;
  }
  if (read(i2c_fd_, idBuf, 3) != 3) {
    return -1;
  }
  if (!PollForAck()) {
    return -1;
  }
  return idBuf[1] << 8 | idBuf[2];
}

void IAPFirmwareUpdater::Erase() {
  LOG(INFO) << "Starting full erase ... ";
  fflush(stdout);

  CHECK(WriteCommand(0x45));
  CHECK(PollForAck());
  uint8_t idBuf[3] = {0xff, 0xff, 0x00};
  CHECK_EQ(write(i2c_fd_, idBuf, 3), 3);
  CHECK(PollForAck(60000));
  LOG(INFO) << "done";
}

bool IAPFirmwareUpdater::WriteFlashChunk(uint32_t address,
                                         uint8_t length,
                                         uint8_t* data) {
  CHECK(WriteCommand(0x31));
  CHECK(PollForAck());
  uint8_t addr[5];
  uint8_t checksum = 0;

  for (int i = 0; i < 4; i++) {
    addr[i] = (address >> (24 - i * 8)) & 0xff;
    checksum ^= addr[i];
  }
  addr[4] = checksum;
  CHECK_EQ(write(i2c_fd_, addr, 5), 5);
  CHECK(PollForAck());

  uint8_t buffer[300] = {0};
  int offset = 0;
  buffer[offset++] = length - 1;

  checksum = length - 1;
  for (int i = 0; i < length; i++) {
    buffer[offset++] = data[i];
    checksum ^= data[i];
  }
  buffer[offset++] = checksum;
  CHECK_EQ(write(i2c_fd_, buffer, offset), offset);
  CHECK(PollForAck());
  return true;
}

bool IAPFirmwareUpdater::ReadFlashChunk(uint32_t address,
                                        uint8_t length,
                                        uint8_t* data) {
  CHECK(WriteCommand(0x11));
  CHECK(PollForAck());
  uint8_t addr[5];
  uint8_t checksum = 0;

  for (int i = 0; i < 4; i++) {
    addr[i] = (address >> (24 - i * 8)) & 0xff;
    checksum ^= addr[i];
  }
  addr[4] = checksum;
  CHECK_EQ(write(i2c_fd_, addr, 5), 5);
  CHECK(PollForAck());

  uint8_t size = length - 1;
  uint8_t len[2] = {size, static_cast<uint8_t>(~size)};
  CHECK_EQ(write(i2c_fd_, len, 2), 2);
  CHECK(PollForAck());

  CHECK_EQ(read(i2c_fd_, data, length), length);
  return true;
}

std::vector<uint8_t> IAPFirmwareUpdater::LoadFirmware(std::string path) {
  std::string buf;
  CHECK(base::ReadFileToString(base::FilePath(path), &buf))
      << "Failed to load firmware: " << path;
  return std::vector<uint8_t>(buf.begin(), buf.end());
}

bool IAPFirmwareUpdater::WriteCommand(uint8_t command) {
  uint8_t buffer[2] = {command, static_cast<uint8_t>(~command)};
  return write(i2c_fd_, buffer, 2) == 2;
}

uint8_t IAPFirmwareUpdater::ReadOneByte() {
  uint8_t byte;
  CHECK_EQ(read(i2c_fd_, &byte, 1), 1);
  return byte;
}

bool IAPFirmwareUpdater::WriteToFile(std::string path, std::string value) {
  return (base::WriteFile(base::FilePath(path), value.c_str(), value.size()) ==
          value.size());
}

int main(int argc, const char* argv[]) {
  DEFINE_string(board, "", "Target board to update");
  DEFINE_string(read, "", "Read current firmware content to file");
  DEFINE_bool(fw_version, false, "Get current firmware version");
  DEFINE_bool(enter_bootloader, false, "Enter bootloader mode");
  DEFINE_bool(leave_bootloader, false, "Leave bootloader mode");
  brillo::FlagHelper::Init(argc, argv, "STM32 IAP firmware updater");

  if (!FLAGS_board.length()) {
    LOG(FATAL) << "No board specified";
  }

  if (boardConfigs.find(FLAGS_board) == boardConfigs.end()) {
    LOG(FATAL) << "Unsupported board " << FLAGS_board;
  }
  config = boardConfigs[FLAGS_board];

  auto updater = IAPFirmwareUpdater(config.i2cBusMin, config.i2cBusMax,
                                    config.i2cSlaveAddress);

  if (FLAGS_fw_version) {
    updater.GetFirmwareVersion();
  } else if (FLAGS_read.length()) {
    updater.ReadFirmware(FLAGS_read);
  } else if (FLAGS_enter_bootloader) {
    // Do nothing as the constructor already enters bootloader
  } else if (FLAGS_leave_bootloader) {
    updater.LeaveBootLoader();
  } else {
    auto commandline = base::CommandLine::ForCurrentProcess();
    auto args = commandline->GetArgs();
    if (args.size() >= 1) {
      updater.Flash(config.flash_address, args[0], true);
    }
  }
  return 0;
}
