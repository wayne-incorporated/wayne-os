// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROSLOG_VIEWER_JOURNAL_H_
#define CROSLOG_VIEWER_JOURNAL_H_

#include "croslog/config.h"

namespace croslog {

class ViewerJournal {
 public:
  ViewerJournal() = default;
  ViewerJournal(const ViewerJournal&) = delete;
  ViewerJournal& operator=(const ViewerJournal&) = delete;

  // Run the plaintext viewer. This may run the runloop to retrieve update
  // events.
  bool Run(const croslog::Config& config);
};

}  // namespace croslog

#endif  // CROSLOG_VIEWER_JOURNAL_H_
