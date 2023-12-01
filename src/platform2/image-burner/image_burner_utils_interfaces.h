// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IMAGE_BURNER_IMAGE_BURNER_UTILS_INTERFACES_H_
#define IMAGE_BURNER_IMAGE_BURNER_UTILS_INTERFACES_H_

#include <stdint.h>

#include <string>

namespace imageburn {

class FileSystemWriter {
 public:
  virtual ~FileSystemWriter() {}
  virtual int Write(const char* data_block, int data_size) = 0;
  virtual bool Open(const char* path) = 0;
  virtual bool Close() = 0;
};

class FileSystemReader {
 public:
  virtual ~FileSystemReader() {}
  virtual bool Open(const char* path) = 0;
  virtual bool Close() = 0;
  virtual int Read(char* data_block, int data_size) = 0;
  virtual int64_t GetSize() = 0;
};

class PathGetter {
 public:
  virtual ~PathGetter() {}
  virtual bool GetRealPath(const char* path, std::string* real_path) = 0;
  virtual bool GetRootPath(std::string* path) = 0;
};

class SignalSender {
 public:
  virtual ~SignalSender() {}
  virtual void SendFinishedSignal(const char* target_path,
                                  bool success,
                                  const char* error_message) = 0;
  virtual void SendProgressSignal(int64_t amount_burnt,
                                  int64_t total_size,
                                  const char* target_path) = 0;
};

}  // namespace imageburn

#endif  // IMAGE_BURNER_IMAGE_BURNER_UTILS_INTERFACES_H_
