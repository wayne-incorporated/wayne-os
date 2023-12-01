// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/anomaly_detector_text_file_reader.h"

#include <stdio.h>

#include <cerrno>
#include <string>
#include <vector>

#include <sys/stat.h>

#include <base/check_op.h>
#include <base/logging.h>

namespace anomaly {

TextFileReader::TextFileReader(const base::FilePath& path)
    : file_path_(path), buf_(kBufferSize_) {
  Open();
}

TextFileReader::~TextFileReader() {}

bool TextFileReader::GetLine(std::string* line) {
  if (!file_.IsValid() && !Open())
    return false;

  bool end_of_file = false;
  while (!end_of_file) {
    for (; pos_ < end_pos_; pos_++) {
      if (buf_[pos_] == '\n') {
        if (skip_next_) {
          skip_next_ = false;
          line_fragment_.clear();
          continue;
        }

        pos_++;
        *line = std::string(line_fragment_.begin(), line_fragment_.end());
        line_fragment_.clear();
        return true;
      }

      line_fragment_.push_back(buf_[pos_]);
    }

    end_of_file = true;
    if (LoadToBuffer()) {
      end_of_file = false;
    }
  }

  return false;
}

bool TextFileReader::Open() {
  if (kMaxOpenRetries_ == open_tries_) {
    // Simply return false if the number of retries have reached the limit.
    return false;
  }
  open_tries_++;

  file_ = base::File(file_path_, base::File::FLAG_OPEN | base::File::FLAG_READ);

  if (!file_.IsValid()) {
    PLOG(WARNING) << "Try #" << open_tries_
                  << " Failed to open file: " << file_path_.value();

    if (kMaxOpenRetries_ == open_tries_) {
      LOG(ERROR) << "Max number of retries to open file " << file_path_.value()
                 << " reached.";
    }
    return false;
  }

  // Reset open_tries_ upon successful Open().
  open_tries_ = 0;

  struct stat st;
  // Use fstat instead of stat to make sure that it gets the inode number for
  // the file that was opened.
  CHECK_GE(fstat(file_.GetPlatformFile(), &st), 0);
  inode_number_ = st.st_ino;
  Clear();
  return true;
}

bool TextFileReader::LoadToBuffer() {
  pos_ = 0;
  end_pos_ = 0;

  int64_t bytes_read = file_.ReadAtCurrentPos(buf_.data(), buf_.size());
  if (bytes_read > 0) {
    end_pos_ = bytes_read;
    return true;
  }

  // In the unlikely event that Open() fails after CheckForNewFile()
  // returned true, TextFileReader will try to open the file again every time
  // GetLine is called before max number of retries is reached.
  if (CheckForNewFile() && Open()) {
    // rsyslog ensures that a line does not get split between restarts (e.g.
    // during log rotation by chromeos-cleanup-logs) meaning the logs at the end
    // of the original file will be a complete line. Therefore we can safely
    // assume that line_fragment_ is empty and thus can be cleared.
    return LoadToBuffer();
  }

  return false;
}

bool TextFileReader::CheckForNewFile() {
  struct stat st;

  int result = stat(file_path_.value().c_str(), &st);

  // This can happen if a the file_ has been moved but a new file at file_path
  // has not been created yet.
  if (result < 0)
    return false;

  return inode_number_ != st.st_ino;
}

void TextFileReader::SeekToEnd() {
  if (!file_.IsValid())
    return;

  skip_next_ = true;
  Clear();
  file_.Seek(base::File::FROM_END, -1);
}

void TextFileReader::SeekToBegin() {
  if (!file_.IsValid())
    return;

  skip_next_ = false;
  Clear();
  file_.Seek(base::File::FROM_BEGIN, 0);
}

void TextFileReader::Clear() {
  line_fragment_.clear();
  end_pos_ = 0;
  pos_ = 0;
}

}  // namespace anomaly
