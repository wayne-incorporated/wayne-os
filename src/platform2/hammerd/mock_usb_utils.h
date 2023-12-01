// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HAMMERD_MOCK_USB_UTILS_H_
#define HAMMERD_MOCK_USB_UTILS_H_

#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "hammerd/usb_utils.h"

namespace hammerd {

ACTION_P(WriteBuf, ptr) {
  memcpy(arg0, ptr, arg1);
  return arg1;
}

class MockUsbEndpoint : public UsbEndpointInterface {
 public:
  MockUsbEndpoint() = default;
  ~MockUsbEndpoint() override = default;
  MOCK_METHOD(bool, UsbSysfsExists, (), (override));
  MOCK_METHOD(UsbConnectStatus, Connect, (), (override));
  MOCK_METHOD(void, Close, (), (override));
  MOCK_METHOD(bool, IsConnected, (), (const, override));
  MOCK_METHOD(int, GetChunkLength, (), (const, override));
  MOCK_METHOD(std::string, GetConfigurationString, (), (const, override));

  // Use implementation identical to UsbEndpoint::Transfer, and test calls
  // to Send and Receive instead.
  int Transfer(const void* outbuf,
               int outlen,
               void* inbuf,
               int inlen,
               bool allow_less,
               unsigned int timeout_ms) override {
    constexpr int kError = -1;
    if (Send(outbuf, outlen, allow_less, timeout_ms) != outlen) {
      return kError;
    }
    if (inlen == 0) {
      return 0;
    }
    return Receive(inbuf, inlen, allow_less, timeout_ms);
  }
  int Send(const void* outbuf,
           int outlen,
           bool allow_less,
           unsigned int timeout_ms) override {
    // We only care about the value of the output buffer.
    auto out_ptr = reinterpret_cast<const uint8_t*>(outbuf);
    std::vector<uint8_t> out(out_ptr, out_ptr + outlen);
    return SendHelper(out, outbuf, outlen);
  }

  MOCK_METHOD(int, SendHelper, (std::vector<uint8_t>, const void*, int));

  MOCK_METHOD(int, Receive, (void*, int, bool, unsigned int), (override));
};

}  // namespace hammerd
#endif  // HAMMERD_MOCK_USB_UTILS_H_
