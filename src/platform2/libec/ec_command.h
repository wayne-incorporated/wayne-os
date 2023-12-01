// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_EC_COMMAND_H_
#define LIBEC_EC_COMMAND_H_

#include <sys/ioctl.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <libusb-1.0/libusb.h>

#include <string>

#include <base/logging.h>
#include <chromeos/ec/cros_ec_dev.h>
#include <chromeos/ec/ec_commands.h>
#include "libec/ec_usb_endpoint.h"

namespace ec {

// Character device exposing the EC command interface.
inline constexpr char kCrosEcPath[] = "/dev/cros_ec";

enum class EcCmdVersionSupportStatus {
  UNKNOWN = 0,
  SUPPORTED = 1,
  UNSUPPORTED = 2,
};

// Upper bound of the host command packet transfer size. Although the EC can
// request a smaller transfer size, this value should never be smaller than
// the largest size the EC can transfer; this value is used to create buffers
// to hold the data to be transferred to and from the EC.
//
// The standard transfer size for v3 commands is is big enough to handle a
// request/response header, flash write offset/size, and 512 bytes of flash
// data:
//   sizeof(ec_host_request):          8
//   sizeof(ec_params_flash_write):    8
//   payload                         512
//                                 = 544 (0x220)
// See
// https://source.chromium.org/chromiumos/_/chromium/chromiumos/platform/ec/+/f3ffccd7d0fe4d0ce60434310795a7bfdaa5274c:chip/stm32/spi.c;l=82;drc=dede4e01ae4c877bb05d671087a6e85a29a0f902
// https://source.chromium.org/chromiumos/_/chromium/chromiumos/platform/ec/+/f3ffccd7d0fe4d0ce60434310795a7bfdaa5274c:chip/npcx/shi.c;l=118;drc=2a5ce905c11807a19035f7a072489df04be4db97
inline constexpr int kMaxPacketSize = 544;

// Empty request or response for the EcCommand template below.
struct EmptyParam {};
// empty struct is one byte in C++, get the size we want instead.
template <typename T>
inline constexpr size_t realsizeof = std::is_empty_v<T> ? 0 : sizeof(T);
// Variable length arrays in request or response for the EcCommand template
// below. T refers to the type of array data and RemainingParams refers to the
// type including remaining parameters in the struct.
template <typename T, typename RemainingParams = EmptyParam>
using ArrayData =
    std::array<T, (kMaxPacketSize - realsizeof<RemainingParams>) / sizeof(T)>;

inline constexpr uint32_t kVersionZero = 0;
inline constexpr uint32_t kVersionOne = 1;

inline constexpr auto kEcCommandUninitializedResult =
    std::numeric_limits<uint32_t>::max();

class EcCommandInterface {
 public:
  virtual ~EcCommandInterface() = default;
  virtual bool Run(int fd) = 0;
  virtual bool Run(ec::EcUsbEndpointInterface& uep) = 0;
  virtual bool RunWithMultipleAttempts(int fd, int num_attempts) = 0;
  virtual uint32_t Version() const = 0;
  virtual uint32_t Command() const = 0;
};

// Helper to build and send the command structures for cros_fp.
template <typename Params, typename Response>
class EcCommand : public EcCommandInterface {
 public:
  explicit EcCommand(uint32_t cmd, uint32_t ver = 0, const Params& req = {})
      : request_(req),
        cmd_({.version = ver,
              .command = cmd,
              // "outsize" is the number of bytes of data going "out"
              // to the EC.
              .outsize = realsizeof<Params>,
              // "insize" is the number of bytes we can accept as the
              // "incoming" data from the EC.
              .insize = realsizeof<Response>,
              .result = kEcCommandUninitializedResult}) {}
  EcCommand(const EcCommand&) = delete;
  EcCommand& operator=(const EcCommand&) = delete;

  ~EcCommand() override = default;

  void SetRespSize(uint32_t insize) { cmd_.insize = insize; }
  void SetReqSize(uint32_t outsize) { cmd_.outsize = outsize; }
  void SetReq(const Params& req) { request_ = req; }

  /**
   * Run an EC command.
   *
   * @param ec_fd file descriptor for the EC device
   * @return true if command runs successfully and response size is same as
   * expected, false otherwise
   *
   * The caller must be careful to only retry EC state-less
   * commands, that can be rerun without consequence.
   */
  bool Run(int ec_fd) override;
  bool Run(ec::EcUsbEndpointInterface& uep) override;

  bool RunWithMultipleAttempts(int fd, int num_attempts) override;

  virtual Response* Resp() { return &response_; }
  virtual const Response* Resp() const { return &response_; }
  virtual uint32_t RespSize() const { return cmd_.insize; }
  Params* Req() { return &request_; }
  const Params* Req() const { return &request_; }
  virtual uint32_t ReqSize() const { return cmd_.outsize; }
  virtual uint32_t Result() const { return cmd_.result; }

  uint32_t Version() const override { return cmd_.version; }
  uint32_t Command() const override { return cmd_.command; }

 protected:
  struct Data {
    struct cros_ec_command_v2 cmd;
    union {
      Params req;
      Response resp;
    };
  };

  bool ErrorTypeCanBeRetried(uint32_t ec_cmd_result);

 private:
  virtual int ioctl(int fd, uint32_t request, Data* data) {
    return ::ioctl(fd, request, data);
  }
  int usb_xfer(const struct usb_endpoint& uep,
               void* outbuf,
               int outlen,
               void* inbuf,
               int inlen);

  unsigned int kUsbXferTimeoutMs = 1000;

  Params request_{};
  Response response_{};
  struct cros_ec_command_v2 cmd_ {};
};

/**
 * @tparam Params request structure
 * @tparam Response response structure
 * @param ec_fd  File descriptor for opened EC device
 * @return true if command is successful in which case cmd.Result() is
 * EC_RES_SUCCESS. false if either the ioctl fails or the command fails on
 * the EC (returns something other than EC_RES_SUCCESS). If the ioctl fails,
 * cmd.Result() will be kEcCommandUninitializedResult. If the command fails
 * on the EC, cmd.Result() will be set to the error returned by the EC (e.g.,
 * EC_RES_BUSY, EC_RES_UNAVAILABLE, etc.) See ec_command_test.cc for details.
 */
template <typename Params, typename Response>
bool EcCommand<Params, Response>::Run(int ec_fd) {
  cmd_.result = kEcCommandUninitializedResult;

  Data data = {.cmd = cmd_, .req = request_};

  int ret = ioctl(ec_fd, CROS_EC_DEV_IOCXCMD_V2, &data);
  if (ret < 0) {
    PLOG(ERROR) << "cros_ec ioctl command 0x" << std::hex << cmd_.command
                << std::dec << " failed";
    return false;
  }

  cmd_.result = data.cmd.result;
  response_ = data.resp;

  // Log errors returned from the EC. INVALID_COMMAND and INVALID_VERSION are
  // commonly used to probe the EC thus more-or-less expected.
  if (cmd_.result == EC_RES_INVALID_COMMAND ||
      cmd_.result == EC_RES_INVALID_VERSION) {
    LOG(INFO) << "cros_ec does not support cmd=" << cmd_.command
              << " ver=" << cmd_.version;
  } else if (cmd_.result != EC_RES_SUCCESS &&
             cmd_.result != EC_RES_IN_PROGRESS) {
    LOG(WARNING) << "cros_ec returned error=" << cmd_.result
                 << " for cmd=" << cmd_.command;
  }

  // Check size in addition to result code to guard against bugs in the
  // command implementation. See ec_command_test.cc for details and example test
  // cases.
  return (static_cast<uint32_t>(ret) == cmd_.insize) &&
         cmd_.result == EC_RES_SUCCESS;
}

template <typename Params, typename Response>
int EcCommand<Params, Response>::usb_xfer(const struct usb_endpoint& uep,
                                          void* outbuf,
                                          int outlen,
                                          void* inbuf,
                                          int inlen) {
  int r, transferred;

  /* Send data out */
  if (outbuf && outlen) {
    transferred = 0;
    r = libusb_bulk_transfer(uep.dev_handle, uep.address,
                             (unsigned char*)outbuf, outlen, &transferred,
                             kUsbXferTimeoutMs);
    if (r < LIBUSB_SUCCESS) {
      LOG(ERROR) << "libusb_bulk_transfer: " << libusb_error_name(r);
      return -1;
    }
    if (transferred != outlen) {
      LOG(ERROR) << "Sent " << transferred << " of " << outlen << " bytes";
      return -1;
    }
    VLOG(1) << "Sent " << outlen << " bytes";
  }

  /* Read reply back */
  if (inbuf && inlen) {
    transferred = 0;
    r = libusb_bulk_transfer(uep.dev_handle, uep.address | 0x80,
                             (unsigned char*)inbuf, inlen, &transferred,
                             kUsbXferTimeoutMs);
    if (r < LIBUSB_SUCCESS) {
      LOG(ERROR) << "libusb_bulk_transfer: " << libusb_error_name(r);
      return -1;
    }
    if (transferred != inlen) {
      LOG(ERROR) << "Received " << transferred << " of " << inlen << " bytes";
      return -1;
    }
    VLOG(1) << "Received " << inlen << " bytes";
  }

  return 0;
}

static inline int sum_bytes(const void* data, int length) {
  const uint8_t* bytes = (const uint8_t*)data;
  int sum = 0;

  for (int i = 0; i < length; i++)
    sum += bytes[i];
  return sum;
}

template <typename Params, typename Response>
bool EcCommand<Params, Response>::Run(ec::EcUsbEndpointInterface& uep) {
  cmd_.result = kEcCommandUninitializedResult;

  if (!uep.ClaimInterface()) {
    LOG(WARNING) << "Failed to claim USB interface";
    return false;
  }

  size_t req_len = sizeof(struct ec_host_request) + cmd_.outsize;
  uint8_t* req_buf = reinterpret_cast<uint8_t*>(malloc(req_len));
  if (req_buf == nullptr) {
    LOG(ERROR) << "Failed to allocate memory for request";
    uep.ReleaseInterface();
    return false;
  }
  struct ec_host_request* req = (struct ec_host_request*)req_buf;
  uint8_t* req_data = req_buf + sizeof(struct ec_host_request);

  req->struct_version = EC_HOST_REQUEST_VERSION; /* 3 */
  req->checksum = 0;
  req->command = cmd_.command;
  req->command_version = cmd_.version;
  req->reserved = 0;
  req->data_len = cmd_.outsize;
  if (cmd_.outsize)
    memcpy(req_data, &request_, cmd_.outsize);
  req->checksum = (uint8_t)(-sum_bytes(req, req_len));

  size_t res_len = sizeof(struct ec_host_response) + cmd_.insize;
  uint8_t* res_buf = reinterpret_cast<uint8_t*>(malloc(res_len));
  if (res_buf == nullptr) {
    LOG(ERROR) << "Failed to allocate memory for response";
    free(req);
    uep.ReleaseInterface();
    return false;
  }
  struct ec_host_response* res = (struct ec_host_response*)res_buf;
  uint8_t* res_data = res_buf + sizeof(struct ec_host_response);
  memset(res_buf, 0, res_len);

  if (usb_xfer(uep.GetEndpointPtr(), req, req_len, res, res_len)) {
    LOG(ERROR) << "Command 0x" << std::hex << cmd_.command << std::dec
               << " over USB failed";
  } else {
    cmd_.result = res->result;
    if (cmd_.insize) {
      memcpy(&response_, res_data, cmd_.insize);
    }
  }

  free(req);
  free(res);

  /* We may fail here but the command was successfully executed. */
  uep.ReleaseInterface();

  return true;
}

template <typename Params, typename Response>
bool EcCommand<Params, Response>::RunWithMultipleAttempts(int fd,
                                                          int num_attempts) {
  for (int retry = 0; retry < num_attempts; retry++) {
    bool ret = Run(fd);

    if (ret) {
      LOG_IF(INFO, retry > 0)
          << "cros_ec ioctl command 0x" << std::hex << cmd_.command << std::dec
          << " succeeded on attempt " << retry + 1 << "/" << num_attempts
          << ".";
      return true;
    }

    if (!ErrorTypeCanBeRetried(Result()) || (errno != ETIMEDOUT)) {
      LOG(ERROR) << "cros_ec ioctl command 0x" << std::hex << cmd_.command
                 << std::dec << " failed on attempt " << retry + 1 << "/"
                 << num_attempts << ", retry is not allowed for error";
      return false;
    }

    LOG(ERROR) << "cros_ec ioctl command 0x" << std::hex << cmd_.command
               << std::dec << " failed on attempt " << retry + 1 << "/"
               << num_attempts;
  }
  return false;
}

template <typename Params, typename Response>
bool EcCommand<Params, Response>::ErrorTypeCanBeRetried(
    uint32_t ec_cmd_result) {
  switch (ec_cmd_result) {
    case kEcCommandUninitializedResult:
    case EC_RES_TIMEOUT:
    case EC_RES_BUSY:
      return true;
    default:
      return false;
  }
}

}  // namespace ec

#endif  // LIBEC_EC_COMMAND_H_
