// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_DATA_MIGRATOR_PLATFORM_H_
#define ARC_VM_DATA_MIGRATOR_PLATFORM_H_

#include <string>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <cryptohome/platform.h>

namespace arc::data_migrator {

// A replacement of base::FilePath::ReferencesParent() which just checks whether
// |path| contains ".." as a component.
bool ReferencesParent(const base::FilePath& path);

// A wrapper class of cryptohome::Platform which just overrides InitializeFile()
// with an alternative implementation of base::FilePath::ReferencesParent().
// It can deal with file names like "..." and " .. " which are rejected by the
// original version of ReferencesParent(). See crbug/181617 for the context.
// Ideally the issue should be fixed in libchrome. However, it was given up in
// consideration of the required amount of work in crbug/464760.
// For now implement a workaround here to confine the effect to the migrator.
// TODO(b/280247852): Remove this class once the above issue is resolved or the
// workaround is decided to be useless.
class Platform : public cryptohome::Platform {
 public:
  Platform() = default;
  Platform(const Platform&) = delete;
  Platform& operator=(const Platform&) = delete;

  ~Platform() override;

  // An alternative implementation of InitializeFile() which can deal with file
  // paths that are valid but rejected by base::FilePath::ReferencesParent().
  // This function first calls the base cryptohome::Platform::InitializeFile(),
  // and falls back to an alternative code path if it fails in such a way that
  // it can be a false positive case of ReferencesParent().
  void InitializeFile(base::File* file,
                      const base::FilePath& path,
                      uint32_t flags) override;
};

}  // namespace arc::data_migrator

#endif  // ARC_VM_DATA_MIGRATOR_PLATFORM_H_
