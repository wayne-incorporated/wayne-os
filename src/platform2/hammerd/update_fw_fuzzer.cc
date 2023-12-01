// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/logging.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "hammerd/fmap_utils.h"
#include "hammerd/fuzzed_ec_image.h"
#include "hammerd/update_fw.h"
#include "hammerd/vb21_struct.h"

namespace hammerd {

class Environment {
 public:
  Environment() { logging::SetMinLogLevel(logging::LOGGING_FATAL); }
};

class FuzzedUsbEndpoint : public UsbEndpointInterface {
 public:
  explicit FuzzedUsbEndpoint(FuzzedDataProvider* const fuzz)
      : fuzz_provider_(fuzz) {}
  ~FuzzedUsbEndpoint() override = default;

  void Close() override {}
  bool UsbSysfsExists() override { return true; }
  UsbConnectStatus Connect() override { return UsbConnectStatus::kSuccess; }
  bool IsConnected() const override {
    return fuzz_provider_->ConsumeIntegral<bool>();
  }
  std::string GetConfigurationString() const override { return "fake"; }

  int GetChunkLength() const override {
    // wMaxPacketSize in USB spec is 2 bytes
    return fuzz_provider_->ConsumeIntegral<uint16_t>();
  }

  int Transfer(const void* outbuf,
               int outlen,
               void* inbuf,
               int inlen,
               bool allow_less,
               unsigned int timeout_ms) override {
    if (inlen == 0)
      return 0;
    return Receive(inbuf, inlen, allow_less, timeout_ms);
  }

  int Send(const void* outbuf,
           int outlen,
           bool allow_less,
           unsigned int timeout_ms) override {
    // Just ignore
    return 0;
  }

  int Receive(void* inbuf,
              int inlen,
              bool allow_less,
              unsigned int timeout_ms) override {
    constexpr int kError = -1;
    size_t remaining_bytes = fuzz_provider_->remaining_bytes();
    if (remaining_bytes < inlen) {
      if (!allow_less)
        return kError;
      inbuf = fuzz_provider_->ConsumeRemainingBytes<uint8_t>().data();
      return remaining_bytes;
    }

    inbuf = fuzz_provider_->ConsumeBytes<uint8_t>(inlen).data();
    return inlen;
  }

 private:
  FuzzedDataProvider* const fuzz_provider_;
};

namespace {

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  uint8_t resp[255];
  constexpr int max_cmd_body_len = 1024;

  FuzzedDataProvider data_provider(data, size);
  FirmwareUpdater fw_updater_(
      std::make_unique<FuzzedUsbEndpoint>(&data_provider));
  FuzzedEcImage ec_image_factory(&data_provider);

  fw_updater_.TryConnectUsb();
  fw_updater_.SendSubcommand(data_provider.ConsumeEnum<UpdateExtraCommand>());
  fw_updater_.InjectEntropyWithPayload(
      data_provider.ConsumeBytesAsString(kEntropySize));
  fw_updater_.SendSubcommandReceiveResponse(
      data_provider.ConsumeEnum<UpdateExtraCommand>(),
      data_provider.ConsumeRandomLengthString(max_cmd_body_len), &resp,
      sizeof(resp));
  fw_updater_.ReadConsole();

  // Only try to transfer if we load a valid image
  if (fw_updater_.LoadEcImage(ec_image_factory.Create())) {
    fw_updater_.GetEcImageVersion();
    fw_updater_.TransferImage(data_provider.ConsumeEnum<SectionName>());
  }

  return 0;
}
}  // namespace
}  // namespace hammerd
