// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "biod/cros_fp_firmware.h"

#include <string>

#include <base/check.h>
#include <base/logging.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/memory_mapped_file.h>
#include <base/notreached.h>

#include <chromeos/ec/ec_commands.h>
#include <fmap.h>

namespace {

constexpr char kFmapRoIdLabel[] = "RO_FRID";
constexpr char kFmapRwIdLabel[] = "RW_FWID";

bool DecodeVersionFromArea(const base::MemoryMappedFile& image,
                           const struct fmap* fmap,
                           const char* area_name,
                           std::string* ver) {
  DCHECK(fmap != nullptr);
  DCHECK(area_name != nullptr);
  DCHECK(ver != nullptr);

  const auto area = fmap_find_area(fmap, area_name);
  if (area == nullptr) {
    LOG(ERROR) << "Failed to find FMAP area " << area_name << ".";
    return false;
  }
  if ((area->offset + area->size) > fmap->size) {
    LOG(ERROR) << "FMAP area " << area_name << " has offset " << area->offset
               << " with size " << area->size
               << ", which spans outside the firmware image, of size "
               << fmap->size << ".";
    return false;
  }

  // area->size can be larger than the printable characters in the buffer
  // std::string(char*, size_t) constructor will not stop at first \0
  const char* str =
      reinterpret_cast<const char*>(&(image.data()[area->offset]));
  *ver = std::string(str, strnlen(str, area->size));
  return true;
}

}  // namespace

namespace biod {

CrosFpFirmware::CrosFpFirmware(const base::FilePath& image_path)
    : path_(image_path) {
  DecodeVersionFromFile();
}

base::FilePath CrosFpFirmware::GetPath() const {
  return path_;
}

bool CrosFpFirmware::IsValid() const {
  return status_ == Status::kOk;
}

CrosFpFirmware::Status CrosFpFirmware::GetStatus() const {
  return status_;
}

std::string CrosFpFirmware::GetStatusString() const {
  return StatusToString(GetStatus());
}

const CrosFpFirmware::ImageVersion& CrosFpFirmware::GetVersion() const {
  return version_;
}

std::string CrosFpFirmware::StatusToString(Status status) {
  switch (status) {
    case CrosFpFirmware::Status::kUninitialized:
      return "Not initialized";
    case CrosFpFirmware::Status::kNotFound:
      return "Firmware file does not exist.";
    case CrosFpFirmware::Status::kBadFmap:
      return "Firmware file has bad FMAP.";
    case CrosFpFirmware::Status::kOpenError:
      return "Failed to open firmware file version.";
    case CrosFpFirmware::Status::kOk:
      return "Firmware file is okay.";
  }

  NOTREACHED();
  return "";
}

void CrosFpFirmware::DecodeVersionFromFile() {
  if (!base::PathExists(path_) || base::DirectoryExists(path_)) {
    LOG(ERROR) << "Failed to find firmware file '" << path_.value() << "'.";
    status_ = Status::kNotFound;
    return;
  }

  base::MemoryMappedFile image;
  if (!image.Initialize(path_) || !image.IsValid()) {
    PLOG(ERROR) << "Failed to open firmware file '" << path_.value() << "'.";
    status_ = Status::kOpenError;
    return;
  }

  auto fmap_offset = fmap_find(image.data(), image.length());
  if (fmap_offset < 0 || fmap_offset >= image.length()) {
    LOG(ERROR) << "Failed to find FMAP inside firmware file '" << path_.value()
               << "'.";
    status_ = Status::kBadFmap;
    return;
  }
  DLOG(INFO) << "FMAP signature found at offset " << fmap_offset << ".";

  base::MemoryMappedFile image_fmap_aligned;
  const base::MemoryMappedFile::Region image_fmap_aligned_region = {
      .offset = fmap_offset,
      .size = image.length() - fmap_offset,
  };
  // MemoryMappedFile doesn't allow sharing the same open file with another
  // MemoryMappedFile nor does it allow mapping multiple file regions,
  // so we need to open the same file again.
  if (!image_fmap_aligned.Initialize(
          base::File(path_, base::File::FLAG_OPEN | base::File::FLAG_READ),
          image_fmap_aligned_region) ||
      !image_fmap_aligned.IsValid()) {
    PLOG(ERROR) << "Failed to open firmware file's fmap region '"
                << path_.value() << "'.";
    status_ = Status::kOpenError;
    return;
  }
  const auto fmap =
      reinterpret_cast<const struct fmap*>(image_fmap_aligned.data());

  // The firmware file's self reported size should not be larger
  // than the file size.
  if (fmap->size > image.length()) {
    LOG(ERROR) << "FMAP reported an image size of " << fmap->size
               << ", which is larger than the entire file size, "
               << image.length() << ", for '" << path_.value() << "'.";
    status_ = Status::kBadFmap;
    return;
  }

  if (!DecodeVersionFromArea(image, fmap, kFmapRoIdLabel,
                             &version_.ro_version)) {
    status_ = Status::kBadFmap;
    return;
  }
  if (!DecodeVersionFromArea(image, fmap, kFmapRwIdLabel,
                             &version_.rw_version)) {
    status_ = Status::kBadFmap;
    return;
  }
  status_ = Status::kOk;
}

}  // namespace biod
