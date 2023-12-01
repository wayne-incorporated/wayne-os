// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//

#ifndef MIDIS_TESTS_SEQ_HANDLER_MOCK_H_
#define MIDIS_TESTS_SEQ_HANDLER_MOCK_H_

#include <gmock/gmock.h>

#include "midis/seq_handler.h"

namespace midis {

class SeqHandlerMock : public SeqHandler {
 public:
  MOCK_METHOD(int,
              SndSeqEventOutputDirect,
              (snd_seq_t*, snd_seq_event_t*),
              (override));
  MOCK_METHOD(int,
              SndSeqEventInput,
              (snd_seq_t*, snd_seq_event_t**),
              (override));
  MOCK_METHOD(int, SndSeqEventInputPending, (snd_seq_t*, int), (override));
  MOCK_METHOD(void, AddSeqDevice, (uint32_t), (override));
  MOCK_METHOD(void, AddSeqPort, (uint32_t, uint32_t), (override));
  MOCK_METHOD(void, RemoveSeqDevice, (uint32_t), (override));
  MOCK_METHOD(void, RemoveSeqPort, (uint32_t, uint32_t), (override));
  MOCK_METHOD(void, ProcessMidiEvent, (snd_seq_event_t*), (override));
};

}  // namespace midis
#endif  //  MIDIS_TESTS_SEQ_HANDLER_MOCK_H_
