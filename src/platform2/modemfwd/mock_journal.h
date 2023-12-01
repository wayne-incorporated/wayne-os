// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MODEMFWD_MOCK_JOURNAL_H_
#define MODEMFWD_MOCK_JOURNAL_H_

#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "modemfwd/journal.h"

namespace modemfwd {

class MockJournal : public Journal {
 public:
  MockJournal() {}
  ~MockJournal() override = default;

  MOCK_METHOD(void,
              MarkStartOfFlashingFirmware,
              (const std::vector<std::string>&,
               const std::string&,
               const std::string&),
              (override));
  MOCK_METHOD(void,
              MarkEndOfFlashingFirmware,
              (const std::string&, const std::string&),
              (override));
};

}  // namespace modemfwd

#endif  // MODEMFWD_MOCK_JOURNAL_H_
