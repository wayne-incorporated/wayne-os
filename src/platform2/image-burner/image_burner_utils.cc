// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "image-burner/image_burner_utils.h"

#include <memory>

#include <sys/stat.h>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/free_deleter.h>
#include <base/strings/stringprintf.h>
#include <rootdev/rootdev.h>

namespace imageburn {
namespace {

const int kFsyncRatio = 1024;

bool RealPath(const char* path, std::string* real_path) {
  std::unique_ptr<char, base::FreeDeleter> result(realpath(path, nullptr));
  if (!result) {
    PLOG(ERROR) << "Couldn't get real path of " << path;
    return false;
  }
  *real_path = result.get();
  return true;
}

}  // namespace

BurnWriter::BurnWriter()
    : fstat_callback_(base::BindRepeating(&base::File::Fstat)) {}

bool BurnWriter::Open(const char* path) {
  if (file_.IsValid())
    return false;

  file_.Initialize(base::FilePath(path),
                   base::File::FLAG_WRITE | base::File::FLAG_OPEN);
  if (!file_.IsValid()) {
    PLOG(ERROR) << "Couldn't open target path " << path;
    return false;
  }

  base::stat_wrapper_t st = {};
  if (fstat_callback_.Run(file_.GetPlatformFile(), &st) != 0) {
    PLOG(ERROR) << "Unable to stat file for path " << path;
    Close();
    return false;
  }

  if (!S_ISBLK(st.st_mode)) {
    PLOG(ERROR) << "Attempt to write to non-block device " << path;
    Close();
    return false;
  }

  LOG(INFO) << path << " opened";
  return true;
}

bool BurnWriter::Close() {
  if (!file_.IsValid())
    return false;
  file_.Close();
  return true;
}

int BurnWriter::Write(const char* data_block, int data_size) {
  const int written = file_.WriteAtCurrentPos(data_block, data_size);
  if (written != data_size) {
    PLOG(ERROR) << "Error writing to target file";
    return written;
  }

  if (!writes_count_ && !file_.Flush()) {
    PLOG(ERROR) << "Error flushing target file.";
    return -1;
  }

  writes_count_++;
  if (writes_count_ == kFsyncRatio)
    writes_count_ = 0;

  return written;
}

BurnReader::BurnReader() {}

bool BurnReader::Open(const char* path) {
  if (file_.IsValid())
    return false;

  file_.Initialize(base::FilePath(path),
                   base::File::FLAG_READ | base::File::FLAG_OPEN);
  if (!file_.IsValid()) {
    PLOG(ERROR) << "Couldn't open source path " << path;
    return false;
  }

  // Obtains the real path of the file associated with the opened file
  // descriptor by resolving the /proc/self/fd/<descriptor> symlink. Compares
  // |path| against the real path determined by /proc/self/fd/<descriptor> to
  // make sure |path| specifies the real path and avoids a potential TOCTOU
  // race between the underlying realpath() and open() call.
  int fd = file_.GetPlatformFile();
  std::string fd_path;
  if (!RealPath(base::StringPrintf("/proc/self/fd/%d", fd).c_str(), &fd_path)) {
    file_.Close();
    return false;
  }
  if (fd_path != path) {
    LOG(ERROR) << path << " isn't a fully resolved path";
    file_.Close();
    return false;
  }

  LOG(INFO) << path << " opened";
  return true;
}

bool BurnReader::Close() {
  if (!file_.IsValid())
    return false;
  file_.Close();
  return true;
}

int BurnReader::Read(char* data_block, int data_size) {
  const int read = file_.ReadAtCurrentPos(data_block, data_size);
  if (read < 0)
    PLOG(ERROR) << "Error reading from source file";
  return read;
}

int64_t BurnReader::GetSize() {
  if (!file_.IsValid())
    return -1;
  return file_.GetLength();
}

bool BurnPathGetter::GetRealPath(const char* path, std::string* real_path) {
  return RealPath(path, real_path);
}

bool BurnPathGetter::GetRootPath(std::string* path) {
  char root_path[PATH_MAX];
  if (rootdev(root_path, sizeof(root_path), true, true)) {
    // Coult not get root path.
    return false;
  }
  *path = root_path;
  return true;
}

}  // namespace imageburn
