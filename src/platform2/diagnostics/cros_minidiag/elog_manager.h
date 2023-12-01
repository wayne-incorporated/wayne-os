// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_MINIDIAG_ELOG_MANAGER_H_
#define DIAGNOSTICS_CROS_MINIDIAG_ELOG_MANAGER_H_

#include <optional>
#include <string>
#include <vector>

#include <base/strings/string_piece.h>

#include "diagnostics/cros_minidiag/minidiag_metrics.h"

namespace cros_minidiag {

// A valid line of event would look like:
// [idx] | [date] | [type] | [data0] | [data1] ...
// Where [idx], [data], [type] are required field and [data*] are optional.
class ElogEvent {
 public:
  explicit ElogEvent(const base::StringPiece& event_string);
  ~ElogEvent();
  // Retrieves the [type] of the event. The [type] is a mandatory field and
  // always the 3rd column in the event string.
  // Return the [type] string, or std::nullopt if an error occurs.
  std::optional<std::string> GetType() const;
  // Retrieves the [subtype] of the event. The [subtype] is an optional field
  // and the 4th column in the event string. Return the [subtype] string, or
  // std::nullopt if the subtype does not exist or an error occurs.
  std::optional<std::string> GetSubType() const;
  // The accessor of data_.
  const std::vector<std::string>& data() const { return data_; }

 private:
  std::vector<std::string> data_;
  // Retrieves the data of the column with specified index.
  // Returns std::nullopt if the data does not exist or an error occurs.
  std::optional<std::string> GetColumn(int idx) const;
};

// ElogManager get the raw output generated from elogtool and parse it line by
// line. If the `previous_last_line` is not empty, only new events that are
// detected after the `previous_last_line` are processed. If the
// `previous_last_line` is empty, all of the events are considered.
class ElogManager {
 public:
  explicit ElogManager(const std::string& elog_string,
                       const std::string& previous_last_line);
  ElogManager(const std::string& elog_string,
              const std::string& previous_last_line,
              MiniDiagMetrics* minidiag_metrics);

  ~ElogManager();
  // The accessor of last_line_.
  const std::string& last_line() const { return last_line_; }
  // Retrieves the number of events.
  int GetEventNum() const;

  // Counts the number of MiniDiag launch events and report via UMA library.
  void ReportMiniDiagLaunch() const;
  void ReportMiniDiagTestReport() const;

 private:
  std::string last_line_;
  std::vector<ElogEvent> elog_events_;

  MiniDiagMetrics default_minidiag_metrics_;
  MiniDiagMetrics* metrics_{nullptr};
};

}  // namespace cros_minidiag
#endif  // DIAGNOSTICS_CROS_MINIDIAG_ELOG_MANAGER_H_
