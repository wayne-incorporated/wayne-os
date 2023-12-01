// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_STORAGE_TOOL_H_
#define DEBUGD_SRC_STORAGE_TOOL_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>

#include "debugd/src/subprocess_tool.h"

namespace debugd {

class StorageTool : public SubprocessTool {
 public:
  StorageTool() = default;
  StorageTool(const StorageTool&) = delete;
  StorageTool& operator=(const StorageTool&) = delete;

  ~StorageTool() override = default;

  std::string Smartctl(const std::string& option);
  std::string Start(const base::ScopedFD& outfd);
  bool IsSupported(const base::FilePath typeFile,
                   const base::FilePath vendFile,
                   std::string* errorMsg);
  std::string Mmc(const std::string& option);
  std::string Ufs(const std::string& option);
  std::string Nvme(const std::string& option);
  std::string NvmeLog(const uint32_t& page_id,
                      const uint32_t& length,
                      bool raw_binary);

 protected:
  virtual const base::FilePath GetRootDevice();

 private:
  // Returns the partition of |dst| as a string. |dst| is expected
  // to be a storage device path (e.g. "/dev/sda1").
  const std::string GetPartition(const std::string& dst);

  // Removes the partition from |dstPath| which is expected
  // to be a storage device path (e.g. "/dev/mmcblk1p2").
  void StripPartition(base::FilePath* dstPath);
};

}  // namespace debugd

#endif  // DEBUGD_SRC_STORAGE_TOOL_H_
