// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_SETUP_ART_CONTAINER_H_
#define ARC_SETUP_ART_CONTAINER_H_

#include <memory>
#include <string>
#include <vector>

#include "arc/setup/android_sdk_version.h"
#include "arc/setup/arc_setup_util.h"

namespace base {
class FilePath;
}  // namespace base

namespace arc {

// The location where the relocated/compiled code is stored.
// Must be synced with dalvik-cache directory in
// container-bundle/*/config.json.
constexpr char kArtDalvikCacheDirectory[] =
    "/mnt/stateful_partition/unencrypted/art-data/dalvik-cache";
constexpr char kFrameworkPath[] =
    "/opt/google/containers/android/rootfs/root/system/framework";

struct ArtContainerPaths;

// A class that relocates boot image and compiles Android code in a container.
class ArtContainer {
 public:
  // Creates an ART container.
  static std::unique_ptr<ArtContainer> CreateContainer(
      ArcMounter* mounter, AndroidSdkVersion sdk_version);

  ~ArtContainer();

  // Relocates images for all isa. When |offset_seed| is not zero, it is used to
  // generate an offset passed to patchoat instead of a random number. When it
  // is zero, ArtContainer uses a random offset.
  bool PatchImage(uint64_t offset_seed);

  // Gets a set of instruction set need to be supported. For example, arm,
  // arm64 or x86.
  static std::vector<std::string> GetIsas();

  static int32_t ChooseRelocationOffsetDeltaForTesting(int32_t min_delta,
                                                       int32_t max_delta,
                                                       uint64_t offset_seed);

 private:
  ArtContainer(ArcMounter* mounter,
               std::unique_ptr<ArtContainerPaths> arc_paths,
               AndroidSdkVersion sdk_version);
  ArtContainer(const ArtContainer&) = delete;
  ArtContainer& operator=(const ArtContainer&) = delete;

  // Starts ART container in a mount namespace.
  bool PatchImageChild(uint64_t offset_seed);

  // Starts ART container and relocates boot images for |isa|.
  bool PatchImage(const std::string& isa, uint64_t offset_seed);

  // Owned by caller.
  ArcMounter* const mounter_;

  // Container path.
  std::unique_ptr<ArtContainerPaths> art_paths_;

  // Android Sdk version.
  const AndroidSdkVersion sdk_version_;
};

}  // namespace arc

#endif  // ARC_SETUP_ART_CONTAINER_H_
