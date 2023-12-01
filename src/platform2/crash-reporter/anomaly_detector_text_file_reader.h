// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This class is intended to be used by LogReader in anomaly_detector_log_reader
//
// Class TextFileReader reads from text file returning a line each time it
// finds the newline character '\n'. If '\n' is not found, it will store
// the characters read so far in line_fragment_ and waits for '\n'. This
// behaviour is useful when read and write is happening concurrently.
//
// If underlying base::File file_ is invalid, TextFileReader tries to reopen the
// file every time GetLine is called until it reaches kMaxOpenRetries_. Once the
// limit is reached, it will simply return false on GetLine().

#ifndef CRASH_REPORTER_ANOMALY_DETECTOR_TEXT_FILE_READER_H_
#define CRASH_REPORTER_ANOMALY_DETECTOR_TEXT_FILE_READER_H_

#include <string>
#include <vector>

#include <base/files/file.h>
#include <base/files/file_util.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

namespace anomaly {

class TextFileReader {
 public:
  explicit TextFileReader(const base::FilePath& path);
  ~TextFileReader();

  // If it finds the next line delimited with '\n', it returns true and assigns
  // the line to the output parameter. If it reaches EOF, it also checks if
  // file_path_ has been replaced by a new file and if so updates file_ to point
  // to the new file.
  bool GetLine(std::string* line);

  // Sets the position of read to -1 from the end of file and sets skip_next_ to
  // true. This results in GetLine discarding all characters from just before
  // the end of the file to the next '\n'.
  // This prevents LogReader from trying to parse a partial line.
  void SeekToEnd();

  // Sets the position of read to the beginning of the file.
  // Only used in test by LogReader class.
  void SeekToBegin();

 private:
  // Opens a file pointed by file_path_ and stores it in file_. It returns true
  // if base::File file_ was opened successfully and false if not. This method
  // will be called once every time GetLine is called until file_ is opened
  // successfully or the number of tries reaches the limit kMaxOpenRetries_.
  bool Open();

  // Reads the content of file_ from position offset_ onwards to buf_.
  bool LoadToBuffer();

  // Clears line_fragment_ and virtually clears the buffer by setting pos_ and
  // end_pos_ to 0.
  void Clear();

  // Check inode number of the file pointed by file_path_ against the current
  // inode number stored. It uses stat(2) system call.
  bool CheckForNewFile();

  const base::FilePath file_path_;
  base::File file_;
  static constexpr int kBufferSize_ = 1024;
  std::vector<char> buf_;
  std::vector<char> line_fragment_;
  // Current position of read within buf_.
  int pos_ = 0;
  // The end position of the used part of the buf_.
  int end_pos_ = 0;
  // The inode number of the file_.
  ino_t inode_number_;
  // If true, skip the next line. This is set to true if SeekToEnd was called to
  // make sure that no partial line is returned as a line.
  bool skip_next_ = false;
  // Number of times Open was called. It is reset on successful Open.
  int open_tries_ = 0;
  // Limit of consecutive unsuccessful Open method call before giving up.
  static constexpr int kMaxOpenRetries_ = 10;

  FRIEND_TEST(AnomalyDetectorFileReaderTest, InvalidFileTest);
  FRIEND_TEST(AnomalyDetectorFileReaderTest, OpenFileTest);
  FRIEND_TEST(AnomalyDetectorFileReaderTest, ReopenFileOnMoveTest);
  FRIEND_TEST(AnomalyDetectorFileReaderConcurrentTest, ReadAppendedTextTest);
  FRIEND_TEST(AnomalyDetectorFileReaderConcurrentTest,
              ReadLineLongerThanBufferTest);
  FRIEND_TEST(AnomalyDetectorFileReaderConcurrentTest, OpenFileRetryTest);
  FRIEND_TEST(AnomalyDetectorFileReaderConcurrentTest,
              OpenFileRetryExceededTest);
  FRIEND_TEST(AnomalyDetectorFileReaderConcurrentTest, HandleFileMoveTest);
};

}  // namespace anomaly

#endif  // CRASH_REPORTER_ANOMALY_DETECTOR_TEXT_FILE_READER_H_
