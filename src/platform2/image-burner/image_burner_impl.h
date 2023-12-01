// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IMAGE_BURNER_IMAGE_BURNER_IMPL_H_
#define IMAGE_BURNER_IMAGE_BURNER_IMPL_H_

#include <string>

#include "image-burner/image_burner_utils_interfaces.h"

#include <gtest/gtest_prod.h>

namespace imageburn {

enum ErrorCode {
  IMAGEBURN_OK = 0,
  IMAGEBURN_ERROR_NULL_SOURCE_PATH,
  IMAGEBURN_ERROR_NULL_TARGET_PATH,
  IMAGEBURN_ERROR_TARGET_PATH_ON_ROOT,
  IMAGEBURN_ERROR_INVALID_TARGET_PATH,
  IMAGEBURN_ERROR_CANNOT_OPEN_SOURCE,
  IMAGEBURN_ERROR_CANNOT_OPEN_TARGET,
  IMAGEBURN_ERROR_CANNOT_CLOSE_SOURCE,
  IMAGEBURN_ERROR_CANNOT_CLOSE_TARGET,
  IMAGEBURN_ERROR_FAILED_READING_SOURCE,
  IMAGEBURN_ERROR_FAILED_WRITING_TO_TARGET,
  IMAGEBURN_ERROR_FAILED_SYNCING_TARGET,
  IMAGEBURN_ERROR_BURNER_NOT_INITIALIZED,
  IMAGEBURN_ERROR_SOURCE_REAL_PATH_NOT_DETERMINED,
  IMAGEBURN_ERROR_SOURCE_PATH_NOT_ALLOWED,
};

class BurnerImpl {
 public:
  BurnerImpl(FileSystemWriter* writer,
             FileSystemReader* reader,
             SignalSender* signal_sender,
             PathGetter* path_getter);

  // Returns error code (error code for success == 0)
  ErrorCode BurnImage(const char* from_path, const char* to_path);

  void InitSignalSender(SignalSender* signal_sender);

  // We use this primary for testing.
  void SetDataBlockSize(int value) { data_block_size_ = value; }

 private:
  FRIEND_TEST(ImageBurnerImplTest, IsSourcePathAllowed);

  bool IsSourcePathAllowed(const std::string& path) const;

  bool ValidateTargetPath(const char* path, ErrorCode* error);
  bool ValidateSourcePath(const char* path,
                          std::string* resolved_path,
                          ErrorCode* error);
  bool DoBurn(const char* from_path, const char* to_path, ErrorCode* error);

  FileSystemWriter* writer_;
  FileSystemReader* reader_;
  SignalSender* signal_sender_;
  PathGetter* path_getter_;

  int data_block_size_;
};

}  // namespace imageburn
#endif  // IMAGE_BURNER_IMAGE_BURNER_IMPL_H_
