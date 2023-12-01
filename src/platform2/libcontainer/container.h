// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBCONTAINER_CONTAINER_H_
#define LIBCONTAINER_CONTAINER_H_

#include <base/files/file_path.h>
#include <base/strings/string_piece.h>
#include <brillo/brillo_export.h>

#include "libcontainer/libcontainer.h"

namespace libcontainer {

class BRILLO_EXPORT Container {
 public:
  Container(base::StringPiece name, const base::FilePath& rundir);
  Container(const Container&) = delete;
  Container& operator=(const Container&) = delete;

  ~Container();

  container* get() const { return container_; }

 private:
  container* const container_;
};

}  // namespace libcontainer

#endif  // LIBCONTAINER_CONTAINER_H_
