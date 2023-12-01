// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/fake_platform/fake_mount_mapper.h"

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/notreached.h>

#include "cryptohome/fake_platform/real_fake_mount_mapping_redirect_factory.h"
#include "cryptohome/fake_platform/test_file_path.h"

namespace cryptohome {

FakeMountMapping::FakeMountMapping(const base::FilePath& source,
                                   const base::FilePath& target,
                                   const base::FilePath& redirect)
    : source_(source), target_(target), redirect_(redirect) {}

const base::FilePath& FakeMountMapping::GetSource() const {
  return source_;
}

const base::FilePath& FakeMountMapping::GetTarget() const {
  return target_;
}

const base::FilePath& FakeMountMapping::GetRedirect() const {
  return redirect_;
}

base::FilePath FakeMountMapping::TranslateTargetToSource(
    const base::FilePath& path) const {
  // AppendRelativePath works only when target is a strict parent, so handle the
  // case when the path is the target separately.
  if (path == target_) {
    return source_;
  }

  base::FilePath result = source_;
  if (!target_.AppendRelativePath(path, &result)) {
    return path;
  }

  return result;
}

base::FilePath FakeMountMapping::TranslateSourceToTarget(
    const base::FilePath& path) const {
  // AppendRelativePath works only when source is a strict parent, so handle the
  // case when the path is the source separately.
  if (path == source_) {
    return target_;
  }

  base::FilePath result = target_;
  if (!source_.AppendRelativePath(path, &result)) {
    return path;
  }

  return result;
}

base::FilePath FakeMountMapping::TranslateTargetToRedirect(
    const base::FilePath& path) const {
  // AppendRelativePath works only when target is a strict parent, so handle the
  // case when the path is the target separately.
  if (path == target_) {
    return redirect_;
  }

  base::FilePath result = redirect_;
  if (!target_.AppendRelativePath(path, &result)) {
    return path;
  }

  return result;
}

base::FilePath FakeMountMapping::TranslateRedirectToTarget(
    const base::FilePath& path) const {
  // AppendRelativePath works only when redirect is a strict parent, so handle
  // the case when the path is the redirect separately.
  if (path == redirect_) {
    return target_;
  }

  base::FilePath result = target_;
  if (!redirect_.AppendRelativePath(path, &result)) {
    return path;
  }

  return result;
}

FakeMountMapper::FakeMountMapper(
    const base::FilePath& tmpfs_rootfs,
    std::unique_ptr<FakeMountMappingRedirectFactory> redirect_factory)
    : tmpfs_rootfs_(tmpfs_rootfs),
      redirect_factory_(std::move(redirect_factory)) {}

FakeMountMapper::~FakeMountMapper() {
  for (const auto& [unused, redirect] : source_to_redirect_) {
    base::DeletePathRecursively(redirect);
  }
}

bool FakeMountMapper::MountImpl(const base::FilePath& source,
                                const base::FilePath& target,
                                const base::FilePath& redirect) {
  // Fail if target is already mounted upon.
  if (target_to_mount_.count(target) != 0) {
    return false;
  }

  // Create new mapping.
  target_to_mount_.emplace(target, FakeMountMapping(source, target, redirect));
  return true;
}

bool FakeMountMapper::Mount(const base::FilePath& source,
                            const base::FilePath& target) {
  base::FilePath redirect;

  // For mounts, we want to have a consistent mapping between the source and
  // redirect, so we have a consistent view across multiple consequent
  // mount-unmount sequences. Thus, if we mount the source for the first time,
  // create a new redirect, otherwise re-use the one already cached.
  if (source_to_redirect_.count(source) != 0) {
    redirect = source_to_redirect_[source];
  } else {
    redirect = redirect_factory_->Create();
    source_to_redirect_.emplace(source, redirect);
  }

  return MountImpl(source, target, redirect);
}

bool FakeMountMapper::Bind(const base::FilePath& source,
                           const base::FilePath& target) {
  // The redirect for Bind is the actual location of the source directory within
  // fake filesystem. That way we can ensure the modifications happen to the
  // same underlying elements, regardless of whether we access it through the
  // source or target path.

  return MountImpl(source, target, ResolvePath(source));
}

bool FakeMountMapper::Unmount(const base::FilePath& target) {
  // Not mounted, return false.
  if (target_to_mount_.count(target) == 0) {
    return false;
  }

  // If the target has sources to other mounts under it, consider it busy.
  for (const auto& [unused, mapping] : target_to_mount_) {
    const base::FilePath& source = mapping.GetSource();
    if (target == source && source == mapping.GetTarget()) {
      // This is a hack to handle self-binding as shared.
      break;
    }
    if (target == source || target.IsParent(source)) {
      return false;
    }
  }

  // All good, remove the mount.
  target_to_mount_.erase(target);
  return true;
}

void FakeMountMapper::ListMountsBySourcePrefix(
    const std::string& source_prefix,
    std::multimap<const base::FilePath, const base::FilePath>* mounts) const {
  DCHECK(mounts);
  mounts->clear();
  for (const auto& [unused, mapping] : target_to_mount_) {
    if (mapping.GetSource().value().rfind(source_prefix, 0) == 0) {
      mounts->emplace(mapping.GetSource(), mapping.GetTarget());
    }
  }
}

void FakeMountMapper::ListMountsBySourcePrefix(
    const base::FilePath& source_prefix,
    std::multimap<const base::FilePath, const base::FilePath>* mounts) const {
  DCHECK(mounts);
  mounts->clear();
  for (const auto& [unused, mapping] : target_to_mount_) {
    const base::FilePath& source = mapping.GetSource();
    if (source == source_prefix || source_prefix.IsParent(source)) {
      mounts->emplace(mapping.GetSource(), mapping.GetTarget());
    }
  }
}

bool FakeMountMapper::IsMounted(const base::FilePath& path) const {
  return target_to_mount_.count(path) != 0;
}

bool FakeMountMapper::IsOnMount(const base::FilePath& path) const {
  for (const auto& [target, mapping] : target_to_mount_) {
    if (mapping.GetTarget() == mapping.GetSource()) {
      // ignore self-binds for resolutions.
      continue;
    }
    if (target == path || target.IsParent(path)) {
      return true;
    }
  }
  return false;
}

std::optional<FakeMountMapping> FakeMountMapper::FindMapping(
    const base::FilePath& path) const {
  std::optional<FakeMountMapping> result;

  for (const auto& [target, mapping] : target_to_mount_) {
    // Find the longest prefix match
    if (mapping.GetTarget() == mapping.GetSource()) {
      // ignore self-binds for resolutions.
      continue;
    }
    if (target == path || target.IsParent(path)) {
      if (!result.has_value() || result->GetTarget().IsParent(target)) {
        result.emplace(mapping);
      }
    }
  }
  return result;
}

base::FilePath FakeMountMapper::ReverseResolvePath(
    const base::FilePath& path, const base::FilePath& expected_parent) const {
  std::unordered_set<base::FilePath> candidates;

  // Get "represented" paths candidates - find all redirects which could be
  // the potential mappings for the `path`, and use those to remap tmpfs path
  // to "represented" path.
  for (const auto& [target, mapping] : target_to_mount_) {
    const base::FilePath redirect = mapping.GetRedirect();
    if (redirect == path || redirect.IsParent(path)) {
      candidates.insert(mapping.TranslateRedirectToTarget(path));
    }
  }

  // If we have not found any candidates, see if the path is on the primary
  // tmpfs path. If it is, make it a candidate by stripping the prefix.
  if (candidates.empty() && tmpfs_rootfs_.IsParent(path)) {
    candidates.insert(fake_platform::StripTestFilePath(tmpfs_rootfs_, path));
  }

  // Walk the mapping chain for each candidate until we stumble upon one which
  // makes the "represented" path to be under `expected_parent`.
  while (!candidates.empty()) {
    std::unordered_set<base::FilePath> next_candidates;
    for (const auto& candidate : candidates) {
      if (expected_parent == candidate || expected_parent.IsParent(candidate)) {
        // Found the candidate which is under the `expected_parent`.
        return candidate;
      }

      // If we can't map it to the next element of chain - drop the candidate.
      std::optional<FakeMountMapping> maybe_mapping = FindMapping(candidate);
      if (maybe_mapping.has_value()) {
        next_candidates.insert(
            maybe_mapping->TranslateTargetToSource(candidate));
      }
    }
    candidates = next_candidates;
  }

  return base::FilePath();
}

base::FilePath FakeMountMapper::ResolvePath(const base::FilePath& path) const {
  // If the path is not on a mount, just return its location within tmpfs.
  if (!IsOnMount(path)) {
    return fake_platform::SpliceTestFilePath(tmpfs_rootfs_, path);
  }

  base::FilePath result = path;
  for (;;) {
    // We are guaranteed to exit the loop, for we return if the source is not
    // itself mapped. The returned path is guaranteed to be on tmpfs for the
    // redirects are always generated on it.
    // This is also not the most efficient way to do the resolution, for the
    // call to IsOnMount within the inner loop effectively makes it O(n^2)
    // complexity for a single resolution step, but it is not performance
    // critical part (test-only code), the expected number of elements is very
    // small, and readability in this case is much more important than a tiny
    // test runtime improvement.
    // TODO(dlunev): add circular mapping prevention.

    // Find the mapping for the result. It must be present because we checked
    // for it before the loop, and we return from the loop if it is not the
    // case.
    std::optional<FakeMountMapping> mapping = FindMapping(result);
    CHECK(mapping.has_value());

    // If the source of the target is not on a mount itself, translate current
    // result onto the mapping's redirect and return.
    if (!IsOnMount(mapping->GetSource())) {
      return mapping->TranslateTargetToRedirect(result);
    }

    // If we are here, then it means we are within a mount chain, and we need
    // to translate relatively to the source, rather than redirect.
    result = mapping->TranslateTargetToSource(result);
  }
  NOTREACHED();
}

}  // namespace cryptohome
