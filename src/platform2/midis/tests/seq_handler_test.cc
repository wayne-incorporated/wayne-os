// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <array>
#include <memory>
#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <brillo/test_helpers.h>
#include <gtest/gtest.h>

#include "midis/device.h"
#include "midis/tests/seq_handler_mock.h"
#include "midis/tests/test_helper.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgPointee;

namespace {

const std::array<uint8_t, 3> kValidBuffer1 = {{0x90, 0x3C, 0x40}};
const std::array<uint8_t, 3> kValidBuffer2 = {{0xC0, 0x0B}};
const std::array<uint8_t, 4> kInvalidBuffer3 = {{0x0A, 0x0B, 0x0C, 0x0D}};

const int kCorrectOutputDirectReturn = 28;
const int kOutClientId = 2;

// Set of mock function calls which we can set expectations on. These are passed
// into the constructor of SeqHandler() when needed.
class CallbacksMock {
 public:
  MOCK_METHOD(void, FakeAddDeviceCallbackMock, (midis::Device*));
  void FakeAddDeviceCallback(std::unique_ptr<midis::Device> device) {
    FakeAddDeviceCallbackMock(device.get());
  }

  MOCK_METHOD(void, RemoveDeviceCallback, (uint32_t, uint32_t));
  MOCK_METHOD(void,
              HandleReceiveDataCallback,
              (uint32_t, uint32_t, uint32_t, const char*, size_t));
  MOCK_METHOD(bool, IsDevicePresentCallback, (uint32_t, uint32_t));
  MOCK_METHOD(bool, IsPortPresentCallback, (uint32_t, uint32_t, uint32_t));
};

}  //  namespace

namespace midis {

class SeqHandlerTest : public ::testing::Test {};

// Check whether Device gets created successfully.
TEST_F(SeqHandlerTest, TestEncodeBytes) {
  auto seq_handler = std::make_unique<SeqHandlerMock>();

  EXPECT_CALL(*seq_handler, SndSeqEventOutputDirect(_, _))
      .WillOnce(Return(kCorrectOutputDirectReturn))
      .WillOnce(Return(kCorrectOutputDirectReturn))
      .WillOnce(Return(kCorrectOutputDirectReturn + 1));

  snd_midi_event_t* encoder;

  // Test that encoding works correctly.
  ASSERT_EQ(snd_midi_event_new(kValidBuffer1.size(), &encoder), 0);
  EXPECT_EQ(seq_handler->EncodeMidiBytes(0, nullptr, kValidBuffer1.data(),
                                         kValidBuffer1.size(), encoder),
            true);
  snd_midi_event_free(encoder);

  // Test that encoding works correctly - 2.
  ASSERT_EQ(snd_midi_event_new(kValidBuffer2.size(), &encoder), 0);
  EXPECT_EQ(seq_handler->EncodeMidiBytes(0, nullptr, kValidBuffer2.data(),
                                         kValidBuffer2.size(), encoder),
            true);
  snd_midi_event_free(encoder);

  // Test for failure when OutputDirect returns incorrect value.
  ASSERT_EQ(snd_midi_event_new(kValidBuffer1.size(), &encoder), 0);
  EXPECT_EQ(seq_handler->EncodeMidiBytes(0, nullptr, kValidBuffer1.data(),
                                         kValidBuffer1.size(), encoder),
            false);
  snd_midi_event_free(encoder);

  // Test for failure when we supply gibberish data.
  ASSERT_EQ(snd_midi_event_new(kInvalidBuffer3.size(), &encoder), 0);
  EXPECT_EQ(seq_handler->EncodeMidiBytes(0, nullptr, kInvalidBuffer3.data(),
                                         kInvalidBuffer3.size(), encoder),
            false);
  snd_midi_event_free(encoder);
}

// Check that ProcessAlsaClientFd errors out correctly for various error inputs.
TEST_F(SeqHandlerTest, TestProcessAlsaClientFdNegative) {
  auto seq_handler = std::make_unique<SeqHandlerMock>();

  // None of these functions should ever be called.
  EXPECT_CALL(*seq_handler, AddSeqDevice(_)).Times(0);
  EXPECT_CALL(*seq_handler, AddSeqPort(_, _)).Times(0);
  EXPECT_CALL(*seq_handler, RemoveSeqDevice(_)).Times(0);
  EXPECT_CALL(*seq_handler, RemoveSeqPort(_, _)).Times(0);
  EXPECT_CALL(*seq_handler, ProcessMidiEvent(_)).Times(0);

  EXPECT_CALL(*seq_handler, SndSeqEventInput(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(nullptr), Return(-ENOSPC)));
  EXPECT_CALL(*seq_handler, SndSeqEventInputPending(_, _)).WillOnce(Return(0));

  seq_handler->ProcessAlsaClientFd();

  snd_seq_event_t invalid_event = {
      // This event type should never show up on this client+port.
      .type = SND_SEQ_EVENT_SONGPOS,
      .source = {
          .client = SND_SEQ_CLIENT_SYSTEM,
          .port = SND_SEQ_PORT_SYSTEM_ANNOUNCE,
      }};

  // Check invalid events.
  EXPECT_CALL(*seq_handler, SndSeqEventInput(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(&invalid_event), Return(0)));
  EXPECT_CALL(*seq_handler, SndSeqEventInputPending(_, _)).WillOnce(Return(0));

  seq_handler->ProcessAlsaClientFd();
}

// Check that ProcessAlsaClientFd handles various valid events correctly.
TEST_F(SeqHandlerTest, TestProcessAlsaClientFdPositive) {
  auto seq_handler = std::make_unique<SeqHandlerMock>();

  snd_seq_event_t valid_event1 = {.type = SND_SEQ_EVENT_PORT_START,
                                  .source = {
                                      .client = SND_SEQ_CLIENT_SYSTEM,
                                      .port = SND_SEQ_PORT_SYSTEM_ANNOUNCE,
                                  }};

  EXPECT_CALL(*seq_handler, AddSeqDevice(_)).Times(1);
  EXPECT_CALL(*seq_handler, AddSeqPort(_, _)).Times(1);
  EXPECT_CALL(*seq_handler, RemoveSeqDevice(_)).Times(0);
  EXPECT_CALL(*seq_handler, RemoveSeqPort(_, _)).Times(0);
  EXPECT_CALL(*seq_handler, ProcessMidiEvent(_)).Times(0);
  EXPECT_CALL(*seq_handler, SndSeqEventInput(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(&valid_event1), Return(0)));
  EXPECT_CALL(*seq_handler, SndSeqEventInputPending(_, _)).WillOnce(Return(0));

  seq_handler->ProcessAlsaClientFd();

  snd_seq_event_t valid_event2 = {
      .type = SND_SEQ_EVENT_CLIENT_EXIT,
      .source = {.client = SND_SEQ_CLIENT_SYSTEM,
                 .port = SND_SEQ_PORT_SYSTEM_ANNOUNCE},
      .data = {.addr = {.client = 3, .port = 4}}};

  seq_handler->out_client_id_ = kOutClientId;
  EXPECT_CALL(*seq_handler, AddSeqDevice(_)).Times(0);
  EXPECT_CALL(*seq_handler, AddSeqPort(_, _)).Times(0);
  EXPECT_CALL(*seq_handler, RemoveSeqDevice(_)).Times(1);
  EXPECT_CALL(*seq_handler, RemoveSeqPort(_, _)).Times(0);
  EXPECT_CALL(*seq_handler, ProcessMidiEvent(_)).Times(0);
  EXPECT_CALL(*seq_handler, SndSeqEventInput(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(&valid_event2), Return(0)));
  EXPECT_CALL(*seq_handler, SndSeqEventInputPending(_, _)).WillOnce(Return(0));

  seq_handler->ProcessAlsaClientFd();
}

// Check that ProcessMidiEvent can successfully decode certain MIDI messages.
// TODO(pmalani): Check SysEx messages.
TEST_F(SeqHandlerTest, TestProcessMidiEventsPositive) {
  CallbacksMock callbacks;
  EXPECT_CALL(callbacks, FakeAddDeviceCallbackMock(_)).Times(0);
  EXPECT_CALL(callbacks, RemoveDeviceCallback(_, _)).Times(0);
  EXPECT_CALL(callbacks, HandleReceiveDataCallback(_, _, _, _, _)).Times(3);
  EXPECT_CALL(callbacks, IsDevicePresentCallback(_, _)).Times(0);
  EXPECT_CALL(callbacks, IsPortPresentCallback(_, _, _)).Times(0);

  auto seq_handler = std::make_unique<SeqHandler>(
      base::BindRepeating(&CallbacksMock::FakeAddDeviceCallback,
                          base::Unretained(&callbacks)),
      base::BindRepeating(&CallbacksMock::RemoveDeviceCallback,
                          base::Unretained(&callbacks)),
      base::BindRepeating(&CallbacksMock::HandleReceiveDataCallback,
                          base::Unretained(&callbacks)),
      base::BindRepeating(&CallbacksMock::IsDevicePresentCallback,
                          base::Unretained(&callbacks)),
      base::BindRepeating(&CallbacksMock::IsPortPresentCallback,
                          base::Unretained(&callbacks)));

  // Initialize decoder.
  seq_handler->decoder_ = SeqHandler::CreateMidiEvent(0);

  snd_seq_event_t valid_event1 = {
      .type = SND_SEQ_EVENT_NOTEON,
      .data = {.raw8 = {{0x00, 0x30, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00}}}};
  seq_handler->ProcessMidiEvent(&valid_event1);

  snd_seq_event_t valid_event2 = {
      .type = SND_SEQ_EVENT_PITCHBEND,
      .data = {
          .raw8 = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe1,
                    0xff, 0xff}},
      }};
  seq_handler->ProcessMidiEvent(&valid_event2);

  snd_seq_event_t valid_event3 = {
      .type = SND_SEQ_EVENT_CONTROLLER,
      .data = {
          .raw8 = {{0x00, 0x00, 0x00, 0x00, 0x47, 0x00, 0x00, 0x00, 0x41, 0x00,
                    0x00, 0x00}},
      }};
  seq_handler->ProcessMidiEvent(&valid_event3);
}

// Check that ProcessMidiEvent can detect invalid MIDI messages.
TEST_F(SeqHandlerTest, TestProcessMidiEventsNegative) {
  CallbacksMock callbacks;
  EXPECT_CALL(callbacks, FakeAddDeviceCallbackMock(_)).Times(0);
  EXPECT_CALL(callbacks, RemoveDeviceCallback(_, _)).Times(0);
  EXPECT_CALL(callbacks, HandleReceiveDataCallback(_, _, _, _, _)).Times(0);
  EXPECT_CALL(callbacks, IsDevicePresentCallback(_, _)).Times(0);
  EXPECT_CALL(callbacks, IsPortPresentCallback(_, _, _)).Times(0);

  auto seq_handler = std::make_unique<SeqHandler>(
      base::BindRepeating(&CallbacksMock::FakeAddDeviceCallback,
                          base::Unretained(&callbacks)),
      base::BindRepeating(&CallbacksMock::RemoveDeviceCallback,
                          base::Unretained(&callbacks)),
      base::BindRepeating(&CallbacksMock::HandleReceiveDataCallback,
                          base::Unretained(&callbacks)),
      base::BindRepeating(&CallbacksMock::IsDevicePresentCallback,
                          base::Unretained(&callbacks)),
      base::BindRepeating(&CallbacksMock::IsPortPresentCallback,
                          base::Unretained(&callbacks)));

  // Initialize decoder.
  seq_handler->decoder_ = SeqHandler::CreateMidiEvent(0);

  snd_seq_event_t invalid_event1 = {
      .type = SND_SEQ_EVENT_PORT_EXIT,
      .data = {
          .raw8 = {{0x00, 0xff, 0x00, 0x00, 0x47, 0x00, 0x00, 0x00, 0x41, 0x00,
                    0x00, 0x00}},
      }};
  seq_handler->ProcessMidiEvent(&invalid_event1);
}

}  // namespace midis
