// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROSLOG_LOG_LINE_READER_H_
#define CROSLOG_LOG_LINE_READER_H_

#include <memory>
#include <string>
#include <tuple>

#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/memory_mapped_file.h"
#include "base/observer_list.h"
#include "base/observer_list_types.h"

#include "croslog/file_change_watcher.h"
#include "croslog/file_map_reader.h"
#include "croslog/log_entry.h"
#include "croslog/log_parser.h"

namespace croslog {

/*
 * This class is responsible for
 * - Reading logs line by line from the file
 * - Automatically switching the file when the file is rotated.
 */
class LogLineReader : public FileChangeWatcher::Observer {
 public:
  class Observer : public base::CheckedObserver {
   public:
    virtual void OnFileChanged(LogLineReader* reader) = 0;
  };

  enum class Backend {
    FILE,
    FILE_FOLLOW,
    MEMORY_FOR_TEST,
  };

  enum class ReadResult {
    // Read successfully
    NO_ERROR,
    // Read but there is no more logs to read
    NO_MORE_LOGS,
    // Error due to the file size change after the previous read.
    ERROR_FILE_TRUNCATED,
  };

  // Sets the maximum limit of length of line.
  static void SetMaxLineLengthForTest(int64_t max_line_length);

  explicit LogLineReader(Backend backend_mode);
  LogLineReader(const LogLineReader&) = delete;
  LogLineReader& operator=(const LogLineReader&) = delete;

  virtual ~LogLineReader();

  // Open the file to read.
  void OpenFile(const base::FilePath& file_path);
  // Open the buffer on memory instead of a file.
  void OpenMemoryBufferForTest(const char* buffer, size_t size);

  // Read the next line from log.
  std::tuple<std::string, ReadResult> Forward();
  // Read the previous line from log.
  std::tuple<std::string, ReadResult> Backward();

  // Set the position to read last.
  void SetPositionLast();
  // Add a observer to retrieve file change events.
  void AddObserver(Observer* obs);
  // Remove a observer to retrieve file change events.
  void RemoveObserver(Observer* obs);

  // Retrieve the current position in bytes.
  off_t position() const { return pos_; }

  // Returns the file path of the target.
  const base::FilePath& file_path() const { return file_path_; }

 private:
  void ReloadRotatedFile();
  void OnFileContentMaybeChanged() override;
  void OnFileNameMaybeChanged() override;

  std::string GetString(std::unique_ptr<FileMapReader::MappedBuffer> buffer,
                        uint64_t offset,
                        uint64_t length) const;

  // Information about the target file. These field are initialized by
  // OpenFile() for either FILE or FILE_FOLLOW.
  base::File file_;
  base::FilePath file_path_;
  ino_t file_inode_ = 0;
  std::unique_ptr<base::MemoryMappedFile> mmap_;

  // This is initialized by OpenFile() for FILE_FOLLOW backend.
  FileChangeWatcher* file_change_watcher_ = nullptr;

  std::unique_ptr<FileMapReader> reader_;
  const Backend backend_mode_;
  bool rotated_ = false;

  // Position of the current read.
  // - Usually be at the first character of line. But it's not when the line is
  //   is too long to read or the file content is unexpectedly changed by
  //   another process.
  // - Must be in the interval of [0, reader_->GetFileSize()].
  //   (|buffer->GetChar(pos)| is invalid if |pos| == |reader_->GetFileSize()|)
  int64_t pos_ = 0;

  base::ObserverList<Observer> observers_;
};

}  // namespace croslog

#endif  // CROSLOG_LOG_LINE_READER_H_
