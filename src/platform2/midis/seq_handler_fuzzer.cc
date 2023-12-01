// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
#include "midis/seq_handler.h"

#include <string>

#include <base/functional/bind.h>
#include <base/logging.h>

#include "midis/device.h"

namespace {

const int kFakeOutputPort = 0;
}

namespace midis {

// We don't have a real device whose callbacks we can run, so instead,
// we just create FakeCallbacks which contains stubs.
class FakeCallbacks {
 public:
  void AddDevice(std::unique_ptr<Device> device) {}
  void RemoveDevice(uint32_t card_num, uint32_t device_num) {}
  void HandleReceiveData(uint32_t card_id,
                         uint32_t device_id,
                         uint32_t port_id,
                         const char* buffer,
                         size_t buf_len) {}
  bool IsDevicePresent(uint32_t card_num, uint32_t device_num) {
    // Unused in the fuzzer, so doesn't matter.
    return true;
  }
  bool IsPortPresent(uint32_t card_num, uint32_t device_num, uint32_t port_id) {
    // Unused in the fuzzer, so doesn't matter.
    return true;
  }
};

// Running a fuzz test on the SeqHandler requires us to set certain
// private variables inside SeqHandler. To allow this to happen,
// we encapsulate the SeqHandler inside a FuzzerRunner class,
// and make FuzzerRunner a friend of SeqHandler.
class SeqHandlerFuzzer {
 public:
  void SetUpSeqHandler() {
    seq_handler_ = std::make_unique<SeqHandler>(
        base::BindRepeating(&FakeCallbacks::AddDevice,
                            base::Unretained(&callbacks_)),
        base::BindRepeating(&FakeCallbacks::RemoveDevice,
                            base::Unretained(&callbacks_)),
        base::BindRepeating(&FakeCallbacks::HandleReceiveData,
                            base::Unretained(&callbacks_)),
        base::BindRepeating(&FakeCallbacks::IsDevicePresent,
                            base::Unretained(&callbacks_)),
        base::BindRepeating(&FakeCallbacks::IsPortPresent,
                            base::Unretained(&callbacks_)));

    seq_handler_->decoder_ = midis::SeqHandler::CreateMidiEvent(0);
  }

  bool SetUpOutputPort() {
    snd_seq_t* tmp_seq = nullptr;

    int err = snd_seq_open(&tmp_seq, "hw", SND_SEQ_OPEN_OUTPUT, 0);
    if (err != 0) {
      LOG(ERROR) << "snd_seq_open fails: " << snd_strerror(err);
      return false;
    }

    SeqHandler::ScopedSeqPtr out_client(tmp_seq);
    tmp_seq = nullptr;
    seq_handler_->out_client_ = std::move(out_client);
    seq_handler_->out_client_id_ =
        snd_seq_client_id(seq_handler_->out_client_.get());
    return true;
  }

  // Send arbitrary data to ProcessMidiEvent() and see what happens.
  void ProcessMidiEvent(const uint8_t* data, size_t size) {
    snd_seq_event_t event;
    size_t bytes_to_copy = sizeof(snd_seq_event_t);
    if (size < bytes_to_copy) {
      bytes_to_copy = size;
    }
    memcpy(&event, data, bytes_to_copy);
    seq_handler_->ProcessMidiEvent(&event);
  }

  void SendMidiData(const uint8_t* data, size_t size) {
    // We don't have a real output port, so we just supply a value.
    // This ALSA seq interface should fail gracefully.
    seq_handler_->SendMidiData(kFakeOutputPort, data, size);
  }

 private:
  std::unique_ptr<SeqHandler> seq_handler_;
  FakeCallbacks callbacks_;
};

struct Environment {
  Environment() { logging::SetMinLogLevel(logging::LOGGING_ERROR); }
};

Environment* env = new Environment();

}  // namespace midis

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  midis::SeqHandlerFuzzer fuzzer;
  fuzzer.SetUpSeqHandler();
  if (!fuzzer.SetUpOutputPort()) {
    abort();
  }
  fuzzer.ProcessMidiEvent(data, size);
  fuzzer.SendMidiData(data, size);
  return 0;
}
