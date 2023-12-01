// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <signal.h>

#include <iostream>
#include <memory>
#include <sys/mount.h>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/files/file_util.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>
#include <brillo/userdb_utils.h>
#include <chromeos/constants/imageloader.h>
#include <imageloader/proto_bindings/imageloader.pb.h>

#include "imageloader/component.h"
#include "imageloader/global_context.h"
#include "imageloader/helper_process_proxy.h"
#include "imageloader/helper_process_receiver.h"
#include "imageloader/imageloader.h"
#include "imageloader/imageloader_impl.h"

namespace {

constexpr uint8_t kProdPublicKey[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00, 0x04, 0x53, 0xd9, 0x6f, 0xb1, 0x92, 0x97, 0x39, 0xa9, 0x97,
    0x18, 0xbe, 0xa7, 0x97, 0x15, 0x06, 0x27, 0x9c, 0x55, 0xa5, 0x40, 0xc1,
    0x0f, 0x98, 0xfa, 0xd8, 0x61, 0x18, 0xee, 0xcf, 0xf3, 0xbb, 0xf9, 0x6e,
    0x6d, 0xa0, 0x66, 0xd2, 0x29, 0xf0, 0x78, 0x5b, 0x7a, 0xab, 0x54, 0xca,
    0x53, 0x16, 0xb0, 0xf9, 0xc4, 0xd8, 0x1d, 0x93, 0x5b, 0x83, 0x6e, 0xa5,
    0x65, 0xe5, 0x71, 0xbc, 0x8d, 0x72, 0x02};

// The path where the components are stored on the device.
constexpr char kComponentsPath[] = "/var/lib/imageloader";
// The location of the container public key.
constexpr char kContainerPublicKeyPath[] =
    "/usr/share/misc/oci-container-key-pub.der";

bool LoadKeyFromFile(const std::string& file, std::vector<uint8_t>* key_out) {
  CHECK(key_out);

  base::FilePath key_file(file);
  std::string key_data;

  // The key should be pretty small.
  if (!ReadFileToString(key_file, &key_data)) {
    LOG(WARNING) << "Could not read key file " << key_file.value();
    return false;
  }

  key_out->clear();
  key_out->insert(key_out->begin(), key_data.begin(), key_data.end());

  return true;
}

bool Init(const std::string& loadedMountsBase) {
  const char* path = loadedMountsBase.c_str();
  if (!base::PathExists(base::FilePath(path))) {
    // Create a folder for loadedMountsBase.
    if (mkdir(path, imageloader::kComponentDirPerms) != 0) {
      PLOG(ERROR) << "Mkdir failed: " << path;
      return false;
    }
    // Mount a tmpfs at loadedMountsBase.
    if (mount("imageloader", path, "tmpfs", MS_NODEV | MS_NOSUID | MS_NOEXEC,
              "mode=0755") < 0) {
      PLOG(ERROR) << "Mount tmpfs failed: " << path;
      return false;
    }
    // Mark the mount point as shared.
    if (mount(nullptr, path, nullptr, MS_SHARED, "") < 0) {
      PLOG(ERROR) << "Mount shared failed: " << path;
      return false;
    }
  }
  return true;
}

bool CreateComponentsPath() {
  // Check if kComponentsPath does not exist or it is not a folder.
  if (!base::DirectoryExists(base::FilePath(kComponentsPath))) {
    // Remove the file at kComponentsPath.
    if (!brillo::DeletePathRecursively(base::FilePath(kComponentsPath))) {
      PLOG(ERROR) << "brillo::DeletePathRecursively failed: "
                  << kComponentsPath;
      return false;
    }
    // Create a folder for kComponentsPath.
    if (mkdir(kComponentsPath, imageloader::kComponentDirPerms) != 0) {
      PLOG(ERROR) << "Mkdir failed: " << kComponentsPath;
      return false;
    }
    // Set ownership user/groups as imageloaderd:imageloaderd
    uid_t uid;
    gid_t gid;
    if (!brillo::userdb::GetUserInfo("imageloaderd", &uid, &gid)) {
      PLOG(ERROR) << "Can not get uid/gid.";
      return false;
    }
    if (chown(kComponentsPath, uid, gid) != 0) {
      PLOG(ERROR) << "Can not set ownership for path: " << kComponentsPath;
      return false;
    }
  }
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  DEFINE_bool(init_only, false,
              "Only executes one-time setup process for imageloader.");
  DEFINE_bool(dry_run, false,
              "Changes unmount_all to print the paths which would be "
              "affected.");
  DEFINE_bool(mount, false,
              "Rather than starting a dbus daemon, verify and mount a single "
              "component and exit immediately.");
  DEFINE_string(mount_component, "",
                "Specifies the name of the component when using --mount.");
  DEFINE_string(mount_dlc, "",
                "Specifies the ID of the DLC when using --mount.");
  DEFINE_string(mount_dlc_package, "package",
                "Specifies the package of the DLC when using --mount.");
  DEFINE_string(dlc_path, "",
                "Specifies the path of the DLC to use when using --mount.");
  DEFINE_string(mount_point, "",
                "Specifies the mountpoint when using either --mount or "
                "--unmount.");
  DEFINE_string(loaded_mounts_base, imageloader::kImageloaderMountBase,
                "Base path where components are mounted (unless --mount_point "
                "is used).");
  DEFINE_int32(mount_helper_fd, -1,
               "Control socket for starting an ImageLoader subprocess. Used "
               "internally.");
  DEFINE_bool(unmount, false,
              "Unmounts the path specified by mount_point and exits "
              "immediately.");
  DEFINE_bool(unmount_all, false,
              "Unmounts all the mountpoints under loaded_mounts_base and exits "
              "immediately.");
  brillo::FlagHelper::Init(argc, argv, "imageloader");

  brillo::OpenLog("imageloader", true);
  brillo::InitLog(brillo::kLogToSyslog);

  if (FLAGS_mount + FLAGS_unmount + FLAGS_unmount_all > 1) {
    LOG(ERROR) << "Only one of --mount, --unmount, and --unmount_all can be "
                  "set at a time.";
    return 1;
  }

  imageloader::GlobalContext g_ctx;
  g_ctx.SetAsCurrent();

  // Create folder for component copies. This ensures that
  // imageloader's storage exists and is owned by `imageloaderd` user.
  if (!CreateComponentsPath()) {
    return 1;
  }

  // Executes the setup process.
  if (!Init(FLAGS_loaded_mounts_base)) {
    return 1;
  }

  if (FLAGS_init_only) {
    return 0;
  }

  // Executing this as the helper process if specified.
  if (FLAGS_mount_helper_fd >= 0) {
    CHECK_GT(FLAGS_mount_helper_fd, -1);
    base::ScopedFD fd(FLAGS_mount_helper_fd);
    imageloader::HelperProcessReceiver root_process(std::move(fd));
    return root_process.Run();
  }

  imageloader::Keys keys;
  // The order of key addition below is important.
  // 1. Prod key, used to sign components in Omaha.
  keys.push_back(std::vector<uint8_t>(std::begin(kProdPublicKey),
                                      std::end(kProdPublicKey)));
  // 2. Container key.
  std::vector<uint8_t> container_key;
  if (LoadKeyFromFile(kContainerPublicKeyPath, &container_key))
    keys.push_back(container_key);

  imageloader::ImageLoaderConfig config(keys, kComponentsPath,
                                        FLAGS_loaded_mounts_base.c_str());
  auto helper_process_proxy =
      std::make_unique<imageloader::HelperProcessProxy>();
  helper_process_proxy->Start(argc, argv, "--mount_helper_fd");

  // Load and mount the specified component and exit.
  if (FLAGS_mount) {
    // Run with minimal privilege.
    imageloader::ImageLoader::EnterSandbox();

    if (!FLAGS_mount_component.empty()) {
      // Access the ImageLoaderImpl directly to avoid needless dbus
      // dependencies, which may not be available at early boot.
      imageloader::ImageLoaderImpl loader(std::move(config));

      std::string component_version =
          loader.GetComponentVersion(FLAGS_mount_component);
      // imageloader returns "" if the component doesn't exist. In this case
      // return 0 so our crash reporting doesn't think something actually went
      // wrong.
      if (component_version.empty())
        return 0;

      if (FLAGS_mount_point.empty()) {
        if (loader
                .LoadComponent(FLAGS_mount_component,
                               helper_process_proxy.get())
                .empty()) {
          LOG(ERROR) << "Failed to verify and mount component: "
                     << FLAGS_mount_component;
          return 1;
        }
      } else if (!loader.LoadComponent(FLAGS_mount_component, FLAGS_mount_point,
                                       helper_process_proxy.get())) {
        LOG(ERROR) << "Failed to verify and mount component: "
                   << FLAGS_mount_component << " at " << FLAGS_mount_point;
        return 1;
      }
      return 0;
    }

    if (!FLAGS_mount_dlc.empty()) {
      if (FLAGS_dlc_path.empty()) {
        LOG(ERROR) << "--dlc_path=path must be set with --mount_dlc";
        return 1;
      }

      imageloader::LoadDlcRequest request;
      request.set_id(FLAGS_mount_dlc);
      request.set_path(FLAGS_dlc_path);
      request.set_package(FLAGS_mount_dlc_package);

      // Access the ImageLoaderImpl directly to avoid needless dbus
      // dependencies, which may not be available at early boot.
      imageloader::ImageLoaderImpl loader(std::move(config));

      return loader.LoadDlc(request, helper_process_proxy.get()).empty() ? 0
                                                                         : 1;
    }

    LOG(ERROR) << "--mount_component=name or --mount_dlc=name must be set "
                  "with --mount";
    return 1;
  }

  // Unmount all component mount points and exit.
  if (FLAGS_unmount_all) {
    // Run with minimal privilege.
    imageloader::ImageLoader::EnterSandbox();

    imageloader::ImageLoaderImpl loader(std::move(config));
    std::vector<std::string> paths;
    const base::FilePath parent_dir(FLAGS_loaded_mounts_base);
    bool success = loader.CleanupAll(FLAGS_dry_run, parent_dir, &paths,
                                     helper_process_proxy.get());
    if (FLAGS_dry_run) {
      for (const auto& path : paths) {
        std::cout << path << "\n";
      }
    }
    if (!success) {
      LOG(ERROR) << "--unmount_all failed!";
      return 1;
    }
    return 0;
  }

  // Unmount a component mount point and exit.
  if (FLAGS_unmount) {
    // Run with minimal privilege.
    imageloader::ImageLoader::EnterSandbox();

    if (FLAGS_mount_point.empty()) {
      LOG(ERROR) << "--mount_point=path must be set with --unmount";
      return 1;
    }

    imageloader::ImageLoaderImpl loader(std::move(config));
    const base::FilePath path(FLAGS_mount_point);
    bool success = loader.Cleanup(path, helper_process_proxy.get());
    if (!success) {
      LOG(ERROR) << "--unmount failed!";
      return 1;
    }
    return 0;
  }

  // Run as a daemon and wait for dbus requests.
  imageloader::ImageLoader daemon(std::move(config),
                                  std::move(helper_process_proxy));
  daemon.Run();

  return 0;
}
