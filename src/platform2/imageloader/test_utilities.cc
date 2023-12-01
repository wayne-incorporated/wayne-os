// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "imageloader/test_utilities.h"

#include <dirent.h>

#include <base/check.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/logging.h>

#include "imageloader/component.h"

namespace base {
void PrintTo(const base::FilePath& path, std::ostream* stream) {
  *stream << path.value();
}
}  // namespace base

namespace imageloader {

base::FilePath GetTestDataPath(const std::string& subdir) {
  const char* src_dir = getenv("SRC");
  CHECK(src_dir != nullptr);
  return base::FilePath(src_dir).Append("testdata").Append(subdir);
}

base::FilePath GetTestComponentPath() {
  return GetTestComponentPath(kTestDataVersion);
}

base::FilePath GetTestComponentPath(const std::string& version) {
  return GetTestDataPath(version + "_chromeos_intel64_PepperFlashPlayer");
}

base::FilePath GetTestOciComponentPath() {
  return GetTestDataPath(kTestOciComponentName);
}

base::FilePath GetMetadataComponentPath() {
  return GetTestDataPath(kMetadataComponentName);
}

base::FilePath GetBadMetadataComponentPath() {
  return GetTestDataPath(kBadMetadataComponentName);
}

base::FilePath GetNonDictMetadataComponentPath() {
  return GetTestDataPath(kNonDictMetadataComponentName);
}

base::FilePath GetNoSignatureComponentPath() {
  return GetTestDataPath(kNoSignatureComponentName);
}

void GetFilesInDir(const base::FilePath& dir, std::list<std::string>* files) {
  base::FileEnumerator file_enum(dir, false, base::FileEnumerator::FILES);
  for (base::FilePath name = file_enum.Next(); !name.empty();
       name = file_enum.Next()) {
    files->emplace_back(name.BaseName().value());
  }
}

}  // namespace imageloader
