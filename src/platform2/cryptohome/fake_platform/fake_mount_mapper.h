// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_FAKE_PLATFORM_FAKE_MOUNT_MAPPER_H_
#define CRYPTOHOME_FAKE_PLATFORM_FAKE_MOUNT_MAPPER_H_

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>

#include <base/files/file_path.h>

#include "cryptohome/fake_platform/real_fake_mount_mapping_redirect_factory.h"

namespace cryptohome {

// A wrapper class for a single mount mapping.
class FakeMountMapping final {
 public:
  FakeMountMapping(const FakeMountMapping& mapping) = default;
  ~FakeMountMapping() = default;

  // Given the path, translate it from the target to the source.
  base::FilePath TranslateTargetToSource(const base::FilePath&) const;

  // Given the path, translate it from the source to the target.
  base::FilePath TranslateSourceToTarget(const base::FilePath&) const;

  // Given the path, translate it from the target to the redirect.
  base::FilePath TranslateTargetToRedirect(const base::FilePath&) const;

  // Given the path, translate it from the redirect to the target.
  base::FilePath TranslateRedirectToTarget(const base::FilePath&) const;

  const base::FilePath& GetSource() const;
  const base::FilePath& GetTarget() const;
  const base::FilePath& GetRedirect() const;

 private:
  FakeMountMapping(const base::FilePath& source,
                   const base::FilePath& target,
                   const base::FilePath& redirect);

  const base::FilePath source_;
  const base::FilePath target_;
  const base::FilePath redirect_;

  friend class FakeMountMapper;
};

// FakeMountMapper maintains the mapping of mounts and provides a method to
// resolve the actual physical location of a path.
// The main internal concept of the class is a "redirect".
// Redirect is a directory, which is a physical location of the files shown
// under the mount target directory.
// In the case of Bind, redirect is a physical location of the
// source within tmpfs.
// In the case of Mount, redirect is a newly created /tmp/<unique id> directory,
// to simulate a persistent storage within a block device or encrypted fs.
class FakeMountMapper final {
 public:
  FakeMountMapper(
      const base::FilePath& tmpfs_rootfs,
      std::unique_ptr<FakeMountMappingRedirectFactory> redirect_factory =
          std::make_unique<RealFakeMountMappingRedirectFactory>());
  ~FakeMountMapper();

  bool Mount(const base::FilePath& source, const base::FilePath& target);
  bool Bind(const base::FilePath& source, const base::FilePath& target);
  bool Unmount(const base::FilePath& target);

  // Returns true if the path is a target of a Bind or Mount.
  bool IsMounted(const base::FilePath& path) const;

  // Returns true if the path is a target or within a target of Bind or Mount.
  bool IsOnMount(const base::FilePath& target) const;

  void ListMountsBySourcePrefix(
      const std::string& source_prefix,
      std::multimap<const base::FilePath, const base::FilePath>* mounts) const;

  void ListMountsBySourcePrefix(
      const base::FilePath& source_prefix,
      std::multimap<const base::FilePath, const base::FilePath>* mounts) const;

  // Translates a path within the "represented" file system to the actual
  // physical location in tmpfs.
  base::FilePath ResolvePath(const base::FilePath& path) const;

  // Transforms a physical location in tmpfs to a logical location within
  // a "represented" filesystem. Since the transformation may yield multiple
  // results (a directory mounted to multiple places), `expected_parent` defines
  // which result should be used - it needs to be a child of `expected_parent`.
  // If matching `expected_parent` also yields multiple results, then the method
  // returns any matching path out of all possible (the choice is not guaranteed
  // to be deterministic and may wary among invocations and program runs).
  base::FilePath ReverseResolvePath(
      const base::FilePath& path, const base::FilePath& expected_parent) const;

 private:
  const base::FilePath tmpfs_rootfs_;
  const std::unique_ptr<FakeMountMappingRedirectFactory> redirect_factory_;

  std::map<base::FilePath, FakeMountMapping> target_to_mount_;
  std::unordered_map<base::FilePath, base::FilePath> source_to_redirect_;

  bool MountImpl(const base::FilePath& source,
                 const base::FilePath& target,
                 const base::FilePath& redirect);

  // Returns mapping if the target is or on the mount, std::nullopt otherwise.
  std::optional<FakeMountMapping> FindMapping(
      const base::FilePath& target) const;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_FAKE_PLATFORM_FAKE_MOUNT_MAPPER_H_
