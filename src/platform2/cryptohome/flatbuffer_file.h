// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_FLATBUFFER_FILE_H_
#define CRYPTOHOME_FLATBUFFER_FILE_H_

#include <optional>
#include <string>

#include <brillo/secure_blob.h>

#include "cryptohome/cryptohome_metrics.h"
#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/platform.h"
#include "cryptohome/username.h"

namespace cryptohome {

class FlatbufferFile final {
 public:
  FlatbufferFile(Platform* platform, const base::FilePath& path);

  FlatbufferFile(const FlatbufferFile&) = delete;
  FlatbufferFile& operator=(const FlatbufferFile&) = delete;

  ~FlatbufferFile();

  // StoreFile writes the |buffer| into the file. |buffer| needs to be the
  // serialized content. |timer_type| is used to report the time spent on
  // storing the file to cryptohome metrics.
  CryptohomeStatus StoreFile(const brillo::Blob& buffer,
                             const TimerType& timer_type) const;
  // Returns the contents of the file as a serialized object. |timer_type| is
  // used to report the time spent on loading the file to the cryptohome
  // metrics.
  CryptohomeStatusOr<brillo::Blob> LoadFile(const TimerType& timer_type) const;

 private:
  Platform* const platform_;
  base::FilePath const path_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_FLATBUFFER_FILE_H_
