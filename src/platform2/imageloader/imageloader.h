// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef IMAGELOADER_IMAGELOADER_H_
#define IMAGELOADER_IMAGELOADER_H_

#include <map>
#include <memory>
#include <string>

#include <signal.h>

#include <base/cancelable_callback.h>
#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <brillo/daemons/dbus_daemon.h>
#include <brillo/errors/error.h>
#include <brillo/process/process_reaper.h>
#include <imageloader/proto_bindings/imageloader.pb.h>

#include "imageloader/dbus_adaptors/org.chromium.ImageLoaderInterface.h"
#include "imageloader/helper_process_proxy.h"
#include "imageloader/imageloader_impl.h"

namespace imageloader {

// This is a utility that handles mounting and unmounting of
// verified filesystem images that might include binaries intended
// to be run as read only.
class ImageLoader : public brillo::DBusServiceDaemon,
                    public org::chromium::ImageLoaderInterfaceInterface {
 public:
  // User and group to run imageloader as.
  static const char kImageLoaderGroupName[];
  static const char kImageLoaderUserName[];

  ImageLoader(ImageLoaderConfig config,
              std::unique_ptr<HelperProcessProxy> proxy);
  ImageLoader(const ImageLoader&) = delete;
  ImageLoader& operator=(const ImageLoader&) = delete;

  ~ImageLoader();

  // Implementations of the public methods interface.
  // Register a component.
  bool RegisterComponent(brillo::ErrorPtr* err,
                         const std::string& name,
                         const std::string& version,
                         const std::string& component_folder_abs_path,
                         bool* out_success) override;

  // TODO(kerrnel): errors should probably be returned using the err object.
  // Get component version given component name.
  bool GetComponentVersion(brillo::ErrorPtr* err,
                           const std::string& name,
                           std::string* out_version) override;

  // Load and mount a component.
  bool LoadComponent(brillo::ErrorPtr* err,
                     const std::string& name,
                     std::string* out_mount_point) override;

  // Load and mount a component from the specified path, which can exist
  // outside of imageloader's reserved storage.
  bool LoadComponentAtPath(brillo::ErrorPtr* err,
                           const std::string& name,
                           const std::string& component_folder_abs_path,
                           std::string* out_mount_point) override;

  // Load and mount a DLC image given the image id and a package id.
  bool LoadDlcImage(brillo::ErrorPtr* err,
                    const std::string& id,
                    const std::string& package,
                    const std::string& a_or_b,
                    std::string* out_mount_point) override;

  // Load and mount a DLC image based on the proto.
  bool LoadDlc(brillo::ErrorPtr* err,
               const LoadDlcRequest& request,
               std::string* out_mount_point) override;

  // Remove a component given component |name|.
  bool RemoveComponent(brillo::ErrorPtr* err,
                       const std::string& name,
                       bool* out_success) override;

  // Get component metadata given component |name|.
  bool GetComponentMetadata(
      brillo::ErrorPtr* err,
      const std::string& name,
      std::map<std::string, std::string>* out_metadata) override;

  // Unmount all mount points given component |name|.
  bool UnmountComponent(brillo::ErrorPtr* err,
                        const std::string& name,
                        bool* out_success) override;

  // Unmount the DLC image mount point given DLC |id| and |package|.
  bool UnloadDlcImage(brillo::ErrorPtr* err,
                      const std::string& id,
                      const std::string& package,
                      bool* out_success) override;

  // Sandboxes the runtime environment, using minijail. This is publicly exposed
  // so that imageloader_main.cc can sandbox when not running as a daemon.
  static void EnterSandbox();

 protected:
  int OnInit() override;
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override;
  void OnShutdown(int* return_code) override;

 private:
  // Callback from ProcessReaper to notify ImageLoader that one of the
  // subprocesses died.
  void OnSubprocessExited(pid_t pid, const siginfo_t& info);
  // ImageLoader exits after 20 seconds of inactivity. This function restarts
  // the timer.
  void PostponeShutdown();

  std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object_;
  ImageLoaderImpl impl_;
  std::unique_ptr<HelperProcessProxy> helper_process_proxy_;
  brillo::ProcessReaper process_reaper_;
  base::CancelableOnceClosure shutdown_callback_;
  org::chromium::ImageLoaderInterfaceAdaptor dbus_adaptor_{this};

  base::WeakPtrFactory<ImageLoader> weak_factory_{this};
};

}  // namespace imageloader

#endif  // IMAGELOADER_IMAGELOADER_H_
