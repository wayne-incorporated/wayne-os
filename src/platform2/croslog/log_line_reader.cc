// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/log_line_reader.h"

#include <algorithm>
#include <string>
#include <utility>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "base/files/file.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/strings/string_util.h"

#include "croslog/file_map_reader.h"

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>

namespace croslog {

namespace {
// Maximum length of line in bytes.
static int64_t g_max_line_length = 1024 * 1024;
}  // namespace

// static
void LogLineReader::SetMaxLineLengthForTest(int64_t max_line_length) {
  CHECK_LE(max_line_length, FileMapReader::GetChunkSizeInBytes());
  CHECK_GE(max_line_length, 0);
  g_max_line_length = max_line_length;
}

LogLineReader::LogLineReader(Backend backend_mode)
    : backend_mode_(backend_mode) {
  // Checks the assumption of this logic.
  DCHECK_GE(FileMapReader::GetChunkSizeInBytes(), g_max_line_length);
}

LogLineReader::~LogLineReader() {
  if (file_change_watcher_)
    file_change_watcher_->RemoveWatch(file_path_);
}

void LogLineReader::OpenFile(const base::FilePath& file_path) {
  CHECK(backend_mode_ == Backend::FILE ||
        backend_mode_ == Backend::FILE_FOLLOW);

  // Ensure the values are not initialized.
  CHECK(file_path_.empty());

  file_ = base::File(file_path, base::File::FLAG_OPEN | base::File::FLAG_READ);
  if (!file_.IsValid()) {
    LOG(ERROR) << "Could not open " << file_path;
    return;
  }
  file_path_ = file_path;
  pos_ = 0;

  // TODO(yoshiki): Use stat_wrapper_t and File::FStat after libchrome uprev.
  struct stat file_stat;
  if (fstat(file_.GetPlatformFile(), &file_stat) == 0)
    file_inode_ = file_stat.st_ino;
  DCHECK_NE(0, file_inode_);

  if (backend_mode_ == Backend::FILE_FOLLOW) {
    // Race may happen when the file rotates just after file opens.
    // TODO(yoshiki): detect the race. Maybe we can use /proc/self/fd/$fd.
    file_change_watcher_ = FileChangeWatcher::GetInstance();
    bool ret = file_change_watcher_->AddWatch(file_path_, this);
    if (!ret) {
      LOG(ERROR) << "Failed to install FileChangeWatcher for " << file_path_
                 << ".";
      file_change_watcher_ = nullptr;
    }
  }

  reader_ = FileMapReader::CreateReader(file_.Duplicate());
}

void LogLineReader::OpenMemoryBufferForTest(const char* buffer, size_t size) {
  CHECK(backend_mode_ == Backend::MEMORY_FOR_TEST);
  reader_ = FileMapReader::CreateFileMapReaderDelegateImplMemoryReaderForTest(
      (const uint8_t*)buffer, size);
}

void LogLineReader::SetPositionLast() {
  // At first, sets the position to EOF.
  pos_ = reader_->GetFileSize();
  DCHECK_LE(0, pos_);

  // Calculates the maximum traversable range in the file and allocate a buffer.
  int64_t pos_traversal_start = std::max(pos_ - g_max_line_length, INT64_C(0));
  int64_t traversal_length = std::min(g_max_line_length, pos_);

  // Allocates a buffer of the segment from |pos_traversal_start| to EOF.
  auto buffer = reader_->MapBuffer(pos_traversal_start, traversal_length);
  CHECK(buffer->valid()) << "Mmap failed. Maybe the file has been truncated.";

  // Traverses in reverse order to find the last LF.
  while (pos_ > pos_traversal_start && buffer->GetChar(pos_ - 1) != '\n')
    pos_--;

  if (pos_ != 0 && pos_ <= pos_traversal_start) {
    LOG(ERROR) << "The last line is too long to handle (more than: "
               << g_max_line_length
               << "bytes). Lines around here may be broken.";
    // Sets the position to the last as a sloppy solution.
    pos_ = reader_->GetFileSize();
  }
}

// Ensure the file path is initialized.
void LogLineReader::ReloadRotatedFile() {
  CHECK(backend_mode_ == Backend::FILE_FOLLOW);

  DCHECK(rotated_);
  DCHECK(PathExists(file_path_));

  rotated_ = false;

  CHECK(file_change_watcher_);
  file_change_watcher_->RemoveWatch(file_path_);

  base::FilePath file_path = file_path_;
  file_path_.clear();
  reader_.reset();
  file_inode_ = 0;
  pos_ = 0;

  OpenFile(file_path);
  if (!file_.IsValid()) {
    LOG(FATAL) << "File looks rotated, but new file can't be opened.";
  }
  reader_ = FileMapReader::CreateReader(file_.Duplicate());
}

std::tuple<std::string, LogLineReader::ReadResult> LogLineReader::Forward() {
  DCHECK_LE(0, pos_);

  if (pos_ > reader_->GetFileSize()) {
    LOG(WARNING) << "Reading next line has failed. Maybe the file has been"
                 << "truncated and the current read position got invalid.";
    return {std::string(), ReadResult::ERROR_FILE_TRUNCATED};
  }

  // Checks the current position is at the beginning of the line.
  if (pos_ != 0) {
    auto buffer = reader_->MapBuffer(pos_ - 1, 1);
    if (!buffer->valid()) {
      // This should be rarely hit, since the truncate check was done at the
      // beginning of this method.
      LOG(ERROR) << "Mmap failed. Maybe the file has been truncated"
                 << " and the current read position got invalid.";
      return {std::string(), ReadResult::ERROR_FILE_TRUNCATED};
    }

    if (buffer->GetChar(pos_ - 1) != '\n') {
      LOG(WARNING) << "The line is odd. The line is too long or the file is"
                   << " unexpectedly changed.";
    }
  }

  // Calculate the maximum traversable size to allocate.
  int64_t traversal_length =
      std::min(g_max_line_length, reader_->GetFileSize() - pos_);
  int64_t pos_traversal_end = pos_ + traversal_length;

  // Allocates a buffer of the segment from |pos_| to |pos_traversal_end|.
  auto buffer = reader_->MapBuffer(pos_, traversal_length);
  if (!buffer->valid()) {
    // This should be rarely hit, since the truncate check was done at the
    // beginning of this method.
    LOG(ERROR) << "Mmap failed. Maybe the file has been truncated"
               << " and the current read position got invalid.";
    return {std::string(), ReadResult::ERROR_FILE_TRUNCATED};
  }

  // Finds the next LF (end of line).
  int64_t pos_line_end = pos_;

  while (pos_line_end < pos_traversal_end &&
         buffer->GetChar(pos_line_end) != '\n') {
    pos_line_end++;
  }

  if (pos_line_end == reader_->GetFileSize()) {
    // Reaches EOF without '\n'.
    int64_t unread_length = reader_->GetFileSize() - pos_;

    if (rotated_ && unread_length == 0 && PathExists(file_path_)) {
      // Free the mapped buffer so that another buffer map is allowed.
      buffer.reset();

      ReloadRotatedFile();
      return Forward();
    }

    // If next file doesn't exist, leave the remaining string.
    // If next file exists, read the remaining string.
    if (!rotated_)
      return {std::string(), ReadResult::NO_MORE_LOGS};

    pos_line_end = reader_->GetFileSize();
  } else if (pos_line_end == (pos_ + g_max_line_length)) {
    LOG(ERROR) << "A line is too long to handle (more than "
               << g_max_line_length
               << "bytes). Lines around here may be broken.";
  }

  // Updates the current position.
  int64_t pos_line_start = pos_;
  int64_t line_length = pos_line_end - pos_;
  pos_ = pos_line_end;

  if (pos_ < reader_->GetFileSize()) {
    // Unless the line is too long, proceed the LF.
    if (buffer->GetChar(pos_) == '\n')
      pos_ += 1;
  }

  return {GetString(std::move(buffer), pos_line_start, line_length),
          ReadResult::NO_ERROR};
}

std::tuple<std::string, LogLineReader::ReadResult> LogLineReader::Backward() {
  DCHECK_LE(0, pos_);
  if (pos_ == 0)
    return {std::string(), ReadResult::NO_MORE_LOGS};

  if (pos_ > reader_->GetFileSize()) {
    LOG(WARNING) << "Reading next line is failed. Maybe the file has been"
                 << "truncated and the current read position got invalid.";
    return {std::string(), ReadResult::ERROR_FILE_TRUNCATED};
  }

  // Calculates the maximum traversable range in the file and allocate a buffer.
  int64_t pos_traversal_start = std::max(pos_ - g_max_line_length, INT64_C(0));
  int64_t traversal_length = pos_ - pos_traversal_start;
  DCHECK_GE(traversal_length, 0);

  // Allocates a buffer of the segment from |pos_traversal_start| to |pos_|.
  auto buffer = reader_->MapBuffer(pos_traversal_start, traversal_length);
  if (!buffer->valid()) {
    // This should be rarely hit, since the truncate check was done at the
    // beginning of this method.
    LOG(ERROR) << "Mmap failed. Maybe the file has been truncated"
               << " and the current read position got invalid.";
    return {std::string(), ReadResult::ERROR_FILE_TRUNCATED};
  }

  // Ensures the current position is the beginning of the previous line.
  if (buffer->GetChar(pos_ - 1) != '\n') {
    LOG(WARNING) << "The line is too long or the file is unexpectedly changed."
                 << " The lines read may be broken.";
  }

  // Finds the next LF (at the beginning of the line).
  int64_t last_start = pos_ - 1;
  while (last_start > pos_traversal_start &&
         buffer->GetChar(last_start - 1) != '\n') {
    last_start--;
  }

  // Ensures the next LF is found.
  if (last_start != 0 && last_start <= pos_traversal_start) {
    LOG(ERROR) << "A line is too long to handle (more than "
               << g_max_line_length
               << "bytes). Lines around here may be broken.";
  }

  // Updates the current position.
  int64_t line_length = pos_ - last_start - 1;
  pos_ = last_start;

  return {GetString(std::move(buffer), last_start, line_length),
          ReadResult::NO_ERROR};
}

void LogLineReader::AddObserver(Observer* obs) {
  observers_.AddObserver(obs);
}

void LogLineReader::RemoveObserver(Observer* obs) {
  observers_.RemoveObserver(obs);
}

std::string LogLineReader::GetString(
    std::unique_ptr<FileMapReader::MappedBuffer> mapped_buffer,
    uint64_t offset,
    uint64_t length) const {
  std::pair<const uint8_t*, size_t> buffer =
      mapped_buffer->GetBuffer(offset, length);

  return std::string(reinterpret_cast<const char*>(buffer.first),
                     buffer.second);
}

void LogLineReader::OnFileContentMaybeChanged() {
  CHECK(backend_mode_ == Backend::FILE_FOLLOW);
  CHECK(file_.IsValid());

  // We didn't consider the case of content change without size change. It
  // shouldn't happen with normal log files.

  // Previous file size at (or shortly before) the previous mmap.
  const int64_t previous_file_size = reader_->GetFileSize();
  // Current file size read from the file system.
  const int64_t current_file_size = file_.GetLength();

  if (previous_file_size != current_file_size) {
    reader_->ApplyFileSizeExpansion();
    for (Observer& obs : observers_)
      obs.OnFileChanged(this);
  }
}

void LogLineReader::OnFileNameMaybeChanged() {
  CHECK(backend_mode_ == Backend::FILE_FOLLOW);

  if (rotated_)
    return;

  if (!PathExists(file_path_)) {
    rotated_ = true;
  } else {
    // TODO(yoshiki): Use stat_wrapper_t and File::Stat after libchrome uprev.
    struct stat file_stat;
    bool inode_changed = ((stat(file_path_.value().c_str(), &file_stat) == 0) &&
                          (file_inode_ != file_stat.st_ino));

    if (inode_changed)
      rotated_ = true;
  }

  if (rotated_) {
    for (Observer& obs : observers_)
      obs.OnFileChanged(this);
  }
}

}  // namespace croslog
