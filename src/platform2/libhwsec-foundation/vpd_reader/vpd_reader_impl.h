// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_VPD_READER_VPD_READER_IMPL_H_
#define LIBHWSEC_FOUNDATION_VPD_READER_VPD_READER_IMPL_H_

#include "libhwsec-foundation/vpd_reader/vpd_reader.h"

#include <memory>
#include <optional>
#include <string>
#include <unordered_map>

#include <brillo/process/process.h>

#include "libhwsec-foundation/hwsec-foundation_export.h"

namespace hwsec_foundation {

class HWSEC_FOUNDATION_EXPORT VpdReaderImpl : public VpdReader {
 public:
  VpdReaderImpl();
  // Constructor with injection for testing.
  explicit VpdReaderImpl(const std::string& vpd_path);

  std::optional<std::string> Get(const std::string& key) override;

 private:
  // The `Process` used to run `vpd_path_`.
  const std::unique_ptr<brillo::Process> process_;
  // The executable path of vpd.
  const std::string vpd_ro_path_;
  // The parsed key-value pairs of the output of `vpd -l`.
  std::optional<std::unordered_map<std::string, std::string>> table_;
};

}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_VPD_READER_VPD_READER_IMPL_H_
