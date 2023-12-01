// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "mtpd/file_entry.h"

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <chromeos/dbus/service_constants.h>

namespace {

MtpFileEntry_FileType LibmtpFileTypeToProtoFileType(
    LIBMTP_filetype_t file_type) {
  switch (file_type) {
    case LIBMTP_FILETYPE_FOLDER:
    case LIBMTP_FILETYPE_JPEG:
    case LIBMTP_FILETYPE_JFIF:
    case LIBMTP_FILETYPE_TIFF:
    case LIBMTP_FILETYPE_BMP:
    case LIBMTP_FILETYPE_GIF:
    case LIBMTP_FILETYPE_PICT:
    case LIBMTP_FILETYPE_PNG:
    case LIBMTP_FILETYPE_WINDOWSIMAGEFORMAT:
    case LIBMTP_FILETYPE_JP2:
    case LIBMTP_FILETYPE_JPX:
    case LIBMTP_FILETYPE_UNKNOWN:
      return static_cast<MtpFileEntry_FileType>(file_type);
    default:
      return MtpFileEntry_FileType_FILE_TYPE_OTHER;
  }
}

}  // namespace

namespace mtpd {

FileEntry::FileEntry(const LIBMTP_file_struct& file)
    : item_id_(file.item_id),
      parent_id_(file.parent_id),
      file_size_(file.filesize),
      modification_time_(file.modificationdate),
      file_type_(file.filetype) {
  if (file.filename)
    file_name_ = file.filename;
}

FileEntry::FileEntry()
    : item_id_(kInvalidFileId),
      parent_id_(kInvalidFileId),
      file_size_(0),
      modification_time_(0),
      file_type_(LIBMTP_FILETYPE_UNKNOWN) {}

FileEntry::~FileEntry() {}

MtpFileEntry FileEntry::ToProtobuf() const {
  MtpFileEntry protobuf;
  protobuf.set_item_id(item_id_);
  protobuf.set_parent_id(parent_id_);
  protobuf.set_file_name(file_name_);
  protobuf.set_file_size(file_size_);
  protobuf.set_modification_time(modification_time_);
  protobuf.set_file_type(LibmtpFileTypeToProtoFileType(file_type_));
  return protobuf;
}

std::vector<uint8_t> FileEntry::ToDBusFormat() const {
  MtpFileEntry protobuf = ToProtobuf();
  size_t size = protobuf.ByteSizeLong();
  std::vector<uint8_t> serialized_proto;
  serialized_proto.resize(size);
  CHECK_GT(size, 0);
  CHECK(protobuf.SerializeToArray(&serialized_proto.front(), size));
  return serialized_proto;
}

// static
std::vector<uint8_t> FileEntry::EmptyFileEntriesToDBusFormat() {
  std::vector<FileEntry> dummy;
  return FileEntriesToDBusFormat(dummy);
}

// static
std::vector<uint8_t> FileEntry::FileEntriesToDBusFormat(
    const std::vector<FileEntry>& entries) {
  MtpFileEntries protobuf;
  std::vector<uint8_t> serialized_proto;

  if (entries.empty())
    return serialized_proto;

  for (size_t i = 0; i < entries.size(); ++i) {
    MtpFileEntry entry_protobuf = entries[i].ToProtobuf();
    MtpFileEntry* added_entry = protobuf.add_file_entries();
    *added_entry = entry_protobuf;
  }
  size_t size = protobuf.ByteSizeLong();
  serialized_proto.resize(size);
  CHECK_GT(size, 0);
  CHECK(protobuf.SerializeToArray(&serialized_proto.front(), size));
  return serialized_proto;
}

}  // namespace mtpd
