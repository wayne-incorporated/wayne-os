// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <memory>
#include <string>
#include <sysexits.h>

#include <base/check.h>
#include <base/task/single_thread_task_runner.h>
#include <brillo/daemons/daemon.h>

#include "u2fd/client/u2f_corp_firmware_version.h"
#include "u2fd/fuzzers/fake_u2f_msg_handler.h"
#include "u2fd/fuzzers/fake_uhid_device.h"
#include "u2fd/hid_interface.h"
#include "u2fd/u2fhid.h"

namespace {

constexpr int kMaxIterations = 100;

class FuzzerLoop : public brillo::Daemon {
 public:
  FuzzerLoop(const uint8_t* data, size_t size) : data_provider_(data, size) {}
  FuzzerLoop(const FuzzerLoop&) = delete;
  FuzzerLoop& operator=(const FuzzerLoop&) = delete;

  ~FuzzerLoop() override = default;

 protected:
  int OnInit() override {
    int exit_code = brillo::Daemon::OnInit();
    if (exit_code != EX_OK) {
      return exit_code;
    }

    fake_u2f_msg_handler_ = std::make_unique<u2f::FakeU2fMessageHandler>();
    auto fake_uhid_device = std::make_unique<u2f::FakeUHidDevice>();
    fake_uhid_device_ = fake_uhid_device.get();
    u2f::U2fCorpFirmwareVersion fake_fw_version;
    std::string fake_dev_id;

    u2fhid_ = std::make_unique<u2f::U2fHid>(std::move(fake_uhid_device),
                                            fake_fw_version, fake_dev_id,
                                            fake_u2f_msg_handler_.get(),
                                            /*u2f_corp_processor=*/nullptr);

    ScheduleSendOutputReport();
    return EX_OK;
  }

 private:
  void ScheduleSendOutputReport() {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(&FuzzerLoop::SendOutputReport, base::Unretained(this)));
  }

  void SendOutputReport() {
    if (data_provider_.remaining_bytes() == 0 || count_ == kMaxIterations) {
      Quit();
      return;
    }
    count_++;

    // Sending the output report to U2fHid::ProcessReport
    fake_uhid_device_->SendOutputReport(
        data_provider_.ConsumeRandomLengthString());

    ScheduleSendOutputReport();
  }

  FuzzedDataProvider data_provider_;

  u2f::FakeUHidDevice* fake_uhid_device_;
  std::unique_ptr<u2f::FakeU2fMessageHandler> fake_u2f_msg_handler_;
  std::unique_ptr<u2f::U2fHid> u2fhid_;
  int count_ = 0;
};
}  // namespace

class Environment {
 public:
  Environment() { logging::SetMinLogLevel(logging::LOG_FATAL); }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  FuzzerLoop loop(data, size);
  CHECK_EQ(loop.Run(), EX_OK);
  return 0;
}
