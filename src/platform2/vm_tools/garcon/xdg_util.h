// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <vector>

#include <base/files/file_path.h>

#ifndef VM_TOOLS_GARCON_XDG_UTIL_H_
#define VM_TOOLS_GARCON_XDG_UTIL_H_

namespace vm_tools {
namespace garcon {
namespace xdg {

// Gets the list of data-directories, based on the XDG base directory
// specification:
// https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html
std::vector<base::FilePath> GetDataDirectories();

}  // namespace xdg
}  // namespace garcon
}  // namespace vm_tools

#endif  // VM_TOOLS_GARCON_XDG_UTIL_H_
