// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_FILE_IO_H_
#define SHILL_FILE_IO_H_

#include <base/no_destructor.h>

namespace shill {

// A POSIX file IO wrapper to allow mocking in unit tests.
class FileIO {
 public:
  virtual ~FileIO();

  // This is a singleton -- use FileIO::GetInstance()->Foo().
  static FileIO* GetInstance();

  virtual ssize_t Write(int fd, const void* buf, size_t count);
  virtual ssize_t Read(int fd, void* buf, size_t count);
  virtual int Close(int fd);
  virtual int SetFdNonBlocking(int fd);

 protected:
  FileIO();
  FileIO(const FileIO&) = delete;
  FileIO& operator=(const FileIO&) = delete;

 private:
  friend class base::NoDestructor<FileIO>;
};

}  // namespace shill

#endif  // SHILL_FILE_IO_H_
