// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef IMAGELOADER_IMAGELOADER_IMPL_H_
#define IMAGELOADER_IMAGELOADER_IMPL_H_

#include <map>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/gtest_prod_util.h>
#include <imageloader/proto_bindings/imageloader.pb.h>

#include "imageloader/helper_process_proxy.h"

namespace imageloader {

using Keys = std::vector<std::vector<uint8_t>>;

struct ImageLoaderConfig {
  ImageLoaderConfig(const Keys& keys,
                    const char* storage_path,
                    const char* mount_path)
      : keys(keys), storage_dir(storage_path), mount_path(mount_path) {}

  Keys keys;
  base::FilePath storage_dir;
  base::FilePath mount_path;
};

class ImageLoaderImpl {
 public:
  // Instantiate an object with a configuration object.
  explicit ImageLoaderImpl(ImageLoaderConfig config)
      : config_(std::move(config)) {}
  ImageLoaderImpl(const ImageLoaderImpl&) = delete;
  ImageLoaderImpl& operator=(const ImageLoaderImpl&) = delete;

  // Register a component.
  bool RegisterComponent(const std::string& name,
                         const std::string& version,
                         const std::string& component_folder_abs_path);

  // Remove a component.
  bool RemoveComponent(const std::string& name);

  // Enumerates all mount point paths with prefix of |parent_dir| and returns
  // them with |paths|. If |dry_run| is true, no mount points are unmounted.
  // If |dry_run| is false, all mount points returned in |paths| are unmounted.
  bool CleanupAll(bool dry_run,
                  const base::FilePath& parent_dir,
                  std::vector<std::string>* paths,
                  HelperProcessProxy* proxy);

  // Cleanup a mount point at |path|.
  bool Cleanup(const base::FilePath& path, HelperProcessProxy* proxy);

  // Cleanup a DLC module image mount point given DLC |id| and |package|.
  bool UnloadDlcImage(const std::string& id,
                      const std::string& package,
                      HelperProcessProxy* proxy);

  // Get component version given component name.
  std::string GetComponentVersion(const std::string& name);

  // Get component metadata given component name.
  bool GetComponentMetadata(const std::string& name,
                            std::map<std::string, std::string>* out_metadata);

  // Load the specified component. This returns the mount point or an empty
  // string on failure.
  std::string LoadComponent(const std::string& name, HelperProcessProxy* proxy);

  // Load the specified DLC module image. This returns the mount point or an
  // empty string on failure.
  std::string LoadDlcImage(const std::string& id,
                           const std::string& package,
                           const std::string& a_or_b,
                           HelperProcessProxy* proxy);

  // Load and mount a DLC image based on the proto.
  // Returns empty string on failure.
  std::string LoadDlc(const LoadDlcRequest& request, HelperProcessProxy* proxy);

  // Load the specified component at a set mount point.
  bool LoadComponent(const std::string& name,
                     const std::string& mount_point,
                     HelperProcessProxy* proxy);

  // Load the specified component from the given path.
  std::string LoadComponentAtPath(const std::string& name,
                                  const base::FilePath& absolute_path,
                                  HelperProcessProxy* proxy);

  // The directory hierarchy for a component consists of the storage_root (i.e.
  // `/var/lib/imageloader`), the component_root
  // (`/var/lib/imageloader/ComponentName`), and the version folder (i.e.
  // `/var/lib/imageloader/ComponentName/23.0.0.205`). That is:
  // [storage_root]/
  // [storage_root]/[component_root]
  // [storage_root]/[component_root]/[version]
  //
  // Inside the `component_root` there is a current version hint file:
  // [storage_root]/[component_root]/latest-version

  // Return the path to latest-version file for |component_name|.
  base::FilePath GetLatestVersionFilePath(const std::string& component_name);

  // Return the path to the [component_root] folder for |component_name|.
  base::FilePath GetComponentRoot(const std::string& component_name);

  // Return the path to a given version of |component_name|.
  base::FilePath GetVersionPath(const std::string& component_name,
                                const std::string& version);

  // Return the path to the current version of |component_name|.
  bool GetPathToCurrentComponentVersion(const std::string& component_name,
                                        base::FilePath* result);

 private:
  FRIEND_TEST_ALL_PREFIXES(ImageLoaderTest, RemoveImageAtPathRemovable);
  FRIEND_TEST_ALL_PREFIXES(ImageLoaderTest, RemoveImageAtPathNotRemovable);
  FRIEND_TEST_ALL_PREFIXES(ImageLoaderTest, ValidIdTest);

  // The configuration traits.
  ImageLoaderConfig config_;

  // Remove component if removable.
  bool RemoveComponentAtPath(const std::string& name,
                             const base::FilePath& component_root,
                             const base::FilePath& component_path);

  // Report if a component name is valid or not.
  static bool IsIdValid(const std::string& id);
};

}  // namespace imageloader

#endif  // IMAGELOADER_IMAGELOADER_IMPL_H_
