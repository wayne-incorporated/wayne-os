// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <libmtp.h>

#include "system_api/proto_bindings/mtp_file_entry.pb.h"

#define COMPILE_ASSERT_MATCH(libmtp_type, protobuf_type)                \
  static_assert(                                                        \
      static_cast<int>(libmtp_type) == static_cast<int>(protobuf_type), \
      "Mismatching types")

COMPILE_ASSERT_MATCH(LIBMTP_FILETYPE_FOLDER,
                     MtpFileEntry_FileType_FILE_TYPE_FOLDER);
COMPILE_ASSERT_MATCH(LIBMTP_FILETYPE_JPEG,
                     MtpFileEntry_FileType_FILE_TYPE_JPEG);
COMPILE_ASSERT_MATCH(LIBMTP_FILETYPE_JFIF,
                     MtpFileEntry_FileType_FILE_TYPE_JFIF);
COMPILE_ASSERT_MATCH(LIBMTP_FILETYPE_TIFF,
                     MtpFileEntry_FileType_FILE_TYPE_TIFF);
COMPILE_ASSERT_MATCH(LIBMTP_FILETYPE_BMP, MtpFileEntry_FileType_FILE_TYPE_BMP);
COMPILE_ASSERT_MATCH(LIBMTP_FILETYPE_GIF, MtpFileEntry_FileType_FILE_TYPE_GIF);
COMPILE_ASSERT_MATCH(LIBMTP_FILETYPE_PICT,
                     MtpFileEntry_FileType_FILE_TYPE_PICT);
COMPILE_ASSERT_MATCH(LIBMTP_FILETYPE_PNG, MtpFileEntry_FileType_FILE_TYPE_PNG);
COMPILE_ASSERT_MATCH(LIBMTP_FILETYPE_WINDOWSIMAGEFORMAT,
                     MtpFileEntry_FileType_FILE_TYPE_WINDOWSIMAGEFORMAT);
COMPILE_ASSERT_MATCH(LIBMTP_FILETYPE_JP2, MtpFileEntry_FileType_FILE_TYPE_JP2);
COMPILE_ASSERT_MATCH(LIBMTP_FILETYPE_JPX, MtpFileEntry_FileType_FILE_TYPE_JPX);
COMPILE_ASSERT_MATCH(LIBMTP_FILETYPE_UNKNOWN,
                     MtpFileEntry_FileType_FILE_TYPE_UNKNOWN);
