// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_CROS_FP_FIRMWARE_H_
#define BIOD_CROS_FP_FIRMWARE_H_

#include <string>

#include <base/files/file_path.h>

namespace biod {

class CrosFpFirmware {
 public:
  enum class Status {
    kUninitialized,
    kOk,
    kNotFound,
    kOpenError,
    kBadFmap,
  };

  struct ImageVersion {
    std::string ro_version;
    std::string rw_version;
  };

  explicit CrosFpFirmware(const base::FilePath& image_path);
  CrosFpFirmware(const CrosFpFirmware&) = delete;
  CrosFpFirmware& operator=(const CrosFpFirmware&) = delete;
  virtual ~CrosFpFirmware() = default;
  base::FilePath GetPath() const;
  bool IsValid() const;
  Status GetStatus() const;
  std::string GetStatusString() const;
  const ImageVersion& GetVersion() const;

 protected:
  CrosFpFirmware() = default;

  void set_status(Status status) { status_ = status; }
  void set_version(const ImageVersion& version) { version_ = version; }

 private:
  base::FilePath path_;
  ImageVersion version_;
  Status status_ = Status::kUninitialized;
  friend class CrosFpFirmwareTest;

  void DecodeVersionFromFile();

  static std::string StatusToString(Status status);
};

}  // namespace biod

#endif  // BIOD_CROS_FP_FIRMWARE_H_
