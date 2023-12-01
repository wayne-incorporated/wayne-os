// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <optional>
#include <utility>

#include <base/check.h>
#include <base/json/json_reader.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/values.h>

#include "imageloader/manifest.h"

namespace imageloader {

namespace {
// The current version of the manifest file.
constexpr int kCurrentManifestVersion = 1;
// The name of the version field in the manifest.
constexpr char kManifestVersionField[] = "manifest-version";
// The name of the component version field in the manifest.
constexpr char kVersionField[] = "version";
// The name of the field containing the image hash.
constexpr char kImageHashField[] = "image-sha256-hash";
// The name of the bool field indicating whether component is removable.
constexpr char kIsRemovableField[] = "is-removable";
// The name of the metadata field.
constexpr char kMetadataField[] = "metadata";
// The name of the field containing the table hash.
constexpr char kTableHashField[] = "table-sha256-hash";
// Optional manifest fields.
constexpr char kFSType[] = "fs-type";
constexpr char kId[] = "id";
constexpr char kPackage[] = "package";
constexpr char kName[] = "name";
constexpr char kImageType[] = "image-type";
constexpr char kPreallocatedSize[] = "pre-allocated-size";
constexpr char kSize[] = "size";
constexpr char kPreloadAllowed[] = "preload-allowed";
constexpr char kFactoryInstall[] = "factory-install";
constexpr char kMountFileRequired[] = "mount-file-required";
constexpr char kReserved[] = "reserved";
constexpr char kCriticalUpdate[] = "critical-update";
constexpr char kUsedBy[] = "used-by";
constexpr char kDaysToPurge[] = "days-to-purge";
constexpr char kDescription[] = "description";
constexpr char kUseLogicalVolume[] = "use-logical-volume";
constexpr char kScaled[] = "scaled";
constexpr char kPowerwashSafe[] = "powerwash-safe";

bool GetSHA256FromString(const std::string& hash_str,
                         std::vector<uint8_t>* bytes) {
  if (!base::HexStringToBytes(hash_str, bytes))
    return false;
  return bytes->size() == 32;
}

// Ensure the metadata entry is a dictionary mapping strings to strings and
// parse it into |out_metadata| and return true if so.
bool ParseMetadata(const base::Value& metadata,
                   std::map<std::string, std::string>* out_metadata) {
  DCHECK(out_metadata);

  if (!metadata.is_dict()) {
    return false;
  }

  for (const auto& item : metadata.GetDict()) {
    if (!item.second.is_string()) {
      LOG(ERROR) << "Key \"" << item.first << "\" did not map to string value";
      return false;
    }

    (*out_metadata)[item.first] = item.second.GetString();
  }

  return true;
}

}  // namespace

// clang-format off
bool Manifest::operator==(const Manifest& rhs) const {
  // NOTE: Update the comparator when a class member is added/removed.
  return
      // Required manifest fields:
      manifest_version() == rhs.manifest_version() &&
      image_sha256() == rhs.image_sha256() &&
      table_sha256() == rhs.table_sha256() &&
      version() == rhs.version() &&
      // Optional manifest fields:
      fs_type() == rhs.fs_type() &&
      id() == rhs.id() &&
      package() == rhs.package() &&
      name() == rhs.name() &&
      image_type() == rhs.image_type() &&
      preallocated_size() == rhs.preallocated_size() &&
      size() == rhs.size() &&
      is_removable() == rhs.is_removable() &&
      preload_allowed() == rhs.preload_allowed() &&
      factory_install() == rhs.factory_install() &&
      mount_file_required() == rhs.mount_file_required() &&
      reserved() == rhs.reserved() &&
      critical_update() == rhs.critical_update() &&
      used_by() == rhs.used_by() &&
      days_to_purge() == rhs.days_to_purge() &&
      description() == rhs.description() &&
      metadata() == rhs.metadata() &&
      use_logical_volume() == rhs.use_logical_volume() &&
      scaled() == rhs.scaled() &&
      powerwash_safe() == rhs.powerwash_safe();
}
// clang-format on

bool Manifest::ParseManifest(const std::string& manifest_raw) {
  // Now deserialize the manifest json and read out the rest of the component.
  auto manifest_value = base::JSONReader::ReadAndReturnValueWithError(
      manifest_raw, base::JSON_PARSE_RFC);
  if (!manifest_value.has_value()) {
    LOG(ERROR) << "Could not parse the manifest file as JSON. Error: "
               << manifest_value.error().message;
    return false;
  }

  if (!manifest_value->is_dict()) {
    LOG(ERROR) << "Manifest file is not dictionary.";
    return false;
  }
  return ParseManifest(manifest_value->GetDict());
}

bool Manifest::ParseManifest(const base::Value::Dict& manifest_dict) {
  // This will have to be changed if the manifest version is bumped.
  std::optional<int> manifest_version =
      manifest_dict.FindInt(kManifestVersionField);
  if (!manifest_version.has_value()) {
    LOG(ERROR) << "Could not parse manifest version field from manifest.";
    return false;
  }
  if (manifest_version != kCurrentManifestVersion) {
    LOG(ERROR) << "Unsupported version of the manifest.";
    return false;
  }
  manifest_version_ = *manifest_version;

  const std::string* image_hash_str = manifest_dict.FindString(kImageHashField);
  if (!image_hash_str) {
    LOG(ERROR) << "Could not parse image hash from manifest.";
    return false;
  }

  if (!GetSHA256FromString(*image_hash_str, &(image_sha256_))) {
    LOG(ERROR) << "Could not convert image hash to bytes.";
    return false;
  }

  const std::string* table_hash_str = manifest_dict.FindString(kTableHashField);
  if (table_hash_str == nullptr) {
    LOG(ERROR) << "Could not parse table hash from manifest.";
    return false;
  }

  if (!GetSHA256FromString(*table_hash_str, &(table_sha256_))) {
    LOG(ERROR) << "Could not convert table hash to bytes.";
    return false;
  }

  const std::string* version = manifest_dict.FindString(kVersionField);
  if (!version) {
    LOG(ERROR) << "Could not parse component version from manifest.";
    return false;
  }
  version_ = *version;

  // The fs_type field is optional, and squashfs by default.
  const std::string* fs_type = manifest_dict.FindString(kFSType);
  if (fs_type) {
    if (*fs_type == "ext4") {
      fs_type_ = FileSystem::kExt4;
    } else if (*fs_type == "squashfs") {
      fs_type_ = FileSystem::kSquashFS;
    } else {
      LOG(ERROR) << "Unsupported file system type: " << *fs_type;
      return false;
    }
  } else {
    fs_type_ = FileSystem::kSquashFS;
  }

  std::optional<bool> is_removable = manifest_dict.FindBool(kIsRemovableField);
  // If |is-removable| field does not exist, by default it is false.
  is_removable_ = is_removable.value_or(false);

  std::optional<bool> preload_allowed = manifest_dict.FindBool(kPreloadAllowed);
  // If |preaload-allowed| field does not exist, by default it is false.
  preload_allowed_ = preload_allowed.value_or(false);

  std::optional<bool> factory_install = manifest_dict.FindBool(kFactoryInstall);
  // If |factory-install| field does not exist, by default it is false.
  factory_install_ = factory_install.value_or(false);

  std::optional<bool> mount_file_required =
      manifest_dict.FindBool(kMountFileRequired);
  // If 'mount-file-required' field does not exist, by default it is false.
  mount_file_required_ = mount_file_required.value_or(false);

  // If 'reserved' field does not exist, by default it is false.
  reserved_ = manifest_dict.FindBool(kReserved).value_or(false);

  // If 'critical-update` field does not exist, by default it is false.
  critical_update_ = manifest_dict.FindBool(kCriticalUpdate).value_or(false);

  // If `use-logical-volume` field does not exist, by default it is false.
  use_logical_volume_ =
      manifest_dict.FindBool(kUseLogicalVolume).value_or(false);

  // If `scaled` field does not exist, by default it is false.
  scaled_ = manifest_dict.FindBool(kScaled).value_or(false);

  // If `powerwash-safe` field does not exist, by default it is false.
  powerwash_safe_ = manifest_dict.FindBool(kPowerwashSafe).value_or(false);

  // All of these fields are optional.
  const std::string* id = manifest_dict.FindString(kId);
  if (id)
    id_ = *id;
  const std::string* package = manifest_dict.FindString(kPackage);
  if (package)
    package_ = *package;
  const std::string* name = manifest_dict.FindString(kName);
  if (name)
    name_ = *name;
  const std::string* image_type = manifest_dict.FindString(kImageType);
  if (image_type)
    image_type_ = *image_type;
  const std::string* used_by = manifest_dict.FindString(kUsedBy);
  if (used_by)
    used_by_ = *used_by;
  const std::string* days_to_purge_str = manifest_dict.FindString(kDaysToPurge);
  if (days_to_purge_str) {
    if (!base::StringToInt64(*days_to_purge_str, &days_to_purge_)) {
      LOG(ERROR) << "Days to purge is malformed: " << *days_to_purge_str;
      return false;
    }
  }
  const std::string* description = manifest_dict.FindString(kDescription);
  if (description)
    description_ = *description;

  const std::string* preallocated_size_str =
      manifest_dict.FindString(kPreallocatedSize);
  if (preallocated_size_str) {
    if (!base::StringToInt64(*preallocated_size_str, &preallocated_size_)) {
      LOG(ERROR) << "Manifest pre-allocated-size was malformed: "
                 << *preallocated_size_str;
      return false;
    }
  }

  const std::string* size_str = manifest_dict.FindString(kSize);
  if (size_str) {
    if (!base::StringToInt64(*size_str, &size_)) {
      LOG(ERROR) << "Manifest size was malformed: " << *size_str;
      return false;
    }
  }

  // Copy out the metadata, if it's there.
  const base::Value* metadata = manifest_dict.Find(kMetadataField);
  if (metadata) {
    if (!ParseMetadata(*metadata, &metadata_)) {
      LOG(ERROR) << "Manifest metadata was malformed";
      return false;
    }
  }

  return true;
}

}  // namespace imageloader
