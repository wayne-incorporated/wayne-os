// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROSLOG_MULTIPLEXER_H_
#define CROSLOG_MULTIPLEXER_H_

#include <memory>
#include <string>
#include <vector>

#include "base/files/file_path.h"
#include "base/observer_list.h"
#include "base/observer_list_types.h"

#include "croslog/log_entry.h"
#include "croslog/log_entry_reader.h"
#include "croslog/log_parser.h"

namespace croslog {

// Read logs from multiple files with merging the lines.
class Multiplexer : public LogLineReader::Observer {
 public:
  class Observer : public base::CheckedObserver {
   public:
    virtual void OnLogFileChanged() = 0;
  };

  Multiplexer();
  Multiplexer(const Multiplexer&) = delete;
  Multiplexer& operator=(const Multiplexer&) = delete;

  // Add a source log file to read.
  void AddSource(base::FilePath log_file,
                 std::unique_ptr<LogParser> parser,
                 bool install_change_watcher);
  // Start watching changes from the currently watched files.
  void StartWatchingFileChange();

  // Read the next line from log.
  MaybeLogEntry Forward();
  // Read the previous line from log.
  MaybeLogEntry Backward();

  // Set the position to read next.
  void SetLinesFromLast(uint32_t pos);

  // Add a observer to retrieve file change events.
  void AddObserver(Observer* obs);
  // Remove a observer to retrieve file change events.
  void RemoveObserver(Observer* obs);

 private:
  struct LogSource {
    LogSource(base::FilePath log_file,
              std::unique_ptr<LogParser> parser_in,
              bool install_change_watcher);

    LogEntryReader reader;
    MaybeLogEntry cache_next_forward;
    MaybeLogEntry cache_next_backward;
  };

  void OnFileChanged(LogLineReader* reader) override;

  std::vector<std::unique_ptr<LogSource>> sources_;
  base::ObserverList<Observer> observers_;
};

}  // namespace croslog

#endif  // CROSLOG_MULTIPLEXER_H_
