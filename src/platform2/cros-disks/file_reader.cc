// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/file_reader.h"

#include <base/check.h>
#include <base/files/file_util.h>

namespace cros_disks {

void FileReader::Close() {
  file_.reset();
}

bool FileReader::Open(const base::FilePath& file_path) {
  file_.reset(base::OpenFile(file_path, "rb"));
  return file_.get() != nullptr;
}

bool FileReader::ReadLine(std::string* line) {
  CHECK(line) << "Invalid argument";

  FILE* fp = file_.get();
  if (fp == nullptr)
    return false;

  line->clear();
  bool line_valid = false;
  int ch;
  while ((ch = fgetc(fp)) != EOF) {
    if (ch == '\n')
      return true;
    line->push_back(static_cast<char>(ch));
    line_valid = true;
  }
  return line_valid;
}

}  // namespace cros_disks
