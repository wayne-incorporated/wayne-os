// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "imageloader/imageloader_impl.h"

#include <linux/magic.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>

#include <memory>
#include <string>

#include <base/containers/adapters.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/important_file_writer.h>
#include <base/json/json_string_value_serializer.h>
#include <base/logging.h>
#include <base/values.h>
#include <base/version.h>
#include <brillo/files/file_util.h>
#include <chromeos/dbus/service_constants.h>

#include "imageloader/component.h"
#include "imageloader/dlc.h"

namespace imageloader {

namespace {

using imageloader::kBadResult;

// The name of the file containing the latest component version.
constexpr char kLatestVersionFile[] = "latest-version";
// The maximum size of the latest-version file.
constexpr int kMaximumLatestVersionSize = 4096;
// Maximum ID length.
constexpr size_t kMaxIdLength = 80;
// Default DLC package name.
constexpr char kDefaultPackage[] = "package";

// |mount_base_path| is the subfolder where all components are mounted.
// For example "/mnt/imageloader."
base::FilePath GetMountPoint(const base::FilePath& mount_base_path,
                             const std::string& component_name,
                             const std::string& component_version) {
  return mount_base_path.Append(component_name).Append(component_version);
}

bool AssertComponentDirPerms(const base::FilePath& path) {
  int mode;
  if (!GetPosixFilePermissions(path, &mode))
    return false;
  return mode == kComponentDirPerms;
}

}  // namespace

// static
bool ImageLoaderImpl::IsIdValid(const std::string& id) {
  // |id| can not be empty or start with a non-alphanumerical character.
  if (id.empty() || id.length() > kMaxIdLength ||
      (!isalpha(id[0]) && !isdigit(id[0]))) {
    LOG(ERROR) << "Invalid ID: " << id;
    return false;
  }
  // id can only contain alphanumerical character plus '_' and '-'.
  for (const char& c : id) {
    if (!isalpha(c) && !isdigit(c) && c != '_' && c != '-') {
      LOG(ERROR) << "Invalid ID: " << id;
      return false;
    }
  }
  return true;
}

bool ImageLoaderImpl::LoadComponent(const std::string& name,
                                    const std::string& mount_point_str,
                                    HelperProcessProxy* proxy) {
  if (!IsIdValid(name)) {
    return false;
  }

  base::FilePath component_path;
  if (!GetPathToCurrentComponentVersion(name, &component_path)) {
    return false;
  }

  std::unique_ptr<Component> component =
      Component::Create(component_path, config_.keys);
  if (!component) {
    LOG(ERROR) << "Failed to initialize component: " << name;
    return false;
  }

  base::FilePath mount_point(mount_point_str);
  return component->Mount(proxy, mount_point);
}

std::string ImageLoaderImpl::LoadComponent(const std::string& name,
                                           HelperProcessProxy* proxy) {
  if (!IsIdValid(name)) {
    return kBadResult;
  }

  base::FilePath component_path;
  if (!GetPathToCurrentComponentVersion(name, &component_path)) {
    return kBadResult;
  }

  return LoadComponentAtPath(name, component_path, proxy);
}

std::string ImageLoaderImpl::LoadDlcImage(const std::string& id,
                                          const std::string& package,
                                          const std::string& a_or_b,
                                          HelperProcessProxy* proxy) {
  if (!IsIdValid(id) || !IsIdValid(package)) {
    return kBadResult;
  }

  Dlc dlc(id, package, config_.mount_path);
  return dlc.Mount(proxy, a_or_b) ? dlc.GetMountPoint().value() : kBadResult;
}

std::string ImageLoaderImpl::LoadDlc(const LoadDlcRequest& request,
                                     HelperProcessProxy* proxy) {
  auto package = request.package();
  if (package.empty())
    package = kDefaultPackage;

  if (!IsIdValid(request.id()) || !IsIdValid(request.package())) {
    return kBadResult;
  }

  Dlc dlc(request.id(), request.package(), config_.mount_path);
  return dlc.Mount(proxy, base::FilePath(request.path()))
             ? dlc.GetMountPoint().value()
             : kBadResult;
}

std::string ImageLoaderImpl::LoadComponentAtPath(
    const std::string& name,
    const base::FilePath& component_path,
    HelperProcessProxy* proxy) {
  if (!IsIdValid(name)) {
    return kBadResult;
  }

  std::unique_ptr<Component> component =
      Component::Create(component_path, config_.keys);
  if (!component) {
    LOG(ERROR) << "Failed to initialize component: " << name;
    return kBadResult;
  }

  base::FilePath mount_point(
      GetMountPoint(config_.mount_path, name, component->manifest().version()));
  return component->Mount(proxy, mount_point) ? mount_point.value()
                                              : kBadResult;
}

bool ImageLoaderImpl::RemoveComponent(const std::string& name) {
  if (!IsIdValid(name)) {
    return false;
  }

  base::FilePath component_root(GetComponentRoot(name));
  base::FilePath component_path;
  if (!GetPathToCurrentComponentVersion(name, &component_path)) {
    LOG(ERROR) << "Failed to get current component version: " << name;
    return false;
  }
  return RemoveComponentAtPath(name, component_root, component_path);
}

bool ImageLoaderImpl::CleanupAll(bool dry_run,
                                 const base::FilePath& parent_dir,
                                 std::vector<std::string>* paths,
                                 HelperProcessProxy* proxy) {
  return proxy->SendUnmountAllCommand(dry_run, parent_dir.value(), paths);
}

bool ImageLoaderImpl::Cleanup(const base::FilePath& path,
                              HelperProcessProxy* proxy) {
  return proxy->SendUnmountCommand(path.value());
}

bool ImageLoaderImpl::UnloadDlcImage(const std::string& id,
                                     const std::string& package,
                                     HelperProcessProxy* proxy) {
  if (!IsIdValid(id)) {
    return false;
  }

  return proxy->SendUnmountCommand(
      Dlc::GetMountPoint(config_.mount_path, id, package).value());
}

bool ImageLoaderImpl::RemoveComponentAtPath(
    const std::string& name,
    const base::FilePath& component_root,
    const base::FilePath& component_path) {
  if (!IsIdValid(name)) {
    return false;
  }

  // Check if component is removable.
  std::unique_ptr<Component> component =
      Component::Create(component_path, config_.keys);
  if (!component) {
    LOG(ERROR) << "Failed to initialize component: " << name;
    return false;
  }
  if (!component->manifest().is_removable()) {
    LOG(ERROR) << "Component is not removable";
    return false;
  }

  // Remove the component (all versions) and latest-version file.
  if (!brillo::DeletePathRecursively(component_root)) {
    LOG(ERROR) << "Failed to delete component.";
    return false;
  }
  return true;
}

bool ImageLoaderImpl::RegisterComponent(
    const std::string& name,
    const std::string& version,
    const std::string& component_folder_abs_path) {
  if (!IsIdValid(name)) {
    return false;
  }

  base::FilePath components_dir(config_.storage_dir);

  // If the directory is writable by others, do not trust the components.
  if (!AssertComponentDirPerms(components_dir))
    return false;

  std::string old_version_hint;
  base::FilePath version_hint_path(GetLatestVersionFilePath(name));
  bool have_old_version = base::PathExists(version_hint_path);
  if (have_old_version) {
    if (!base::ReadFileToStringWithMaxSize(version_hint_path, &old_version_hint,
                                           kMaximumLatestVersionSize)) {
      return false;
    }

    // Check for version rollback.
    base::Version current_version(old_version_hint);
    base::Version new_version(version);
    if (!new_version.IsValid()) {
      return false;
    }

    if (current_version.IsValid() && new_version <= current_version) {
      LOG(ERROR) << "Version [" << new_version << "] is not newer than ["
                 << current_version << "] for component [" << name
                 << "] and cannot be registered.";
      return false;
    }
  }

  // Check if this specific component already exists in the filesystem.
  base::FilePath component_root(GetComponentRoot(name));
  if (!base::PathExists(component_root)) {
    if (mkdir(component_root.value().c_str(), kComponentDirPerms) != 0) {
      PLOG(ERROR) << "Could not create component specific directory.";
      return false;
    }
  }

  std::unique_ptr<Component> component = Component::Create(
      base::FilePath(component_folder_abs_path), config_.keys);
  if (!component)
    return false;

  // Check that the reported version matches the component manifest version.
  if (component->manifest().version() != version) {
    LOG(ERROR) << "Version in signed manifest does not match the reported "
                  "component version.";
    return false;
  }

  // Take ownership of the component and verify it.
  base::FilePath version_path(GetVersionPath(name, version));
  // If |version_path| exists but was not the active version, ImageLoader
  // probably crashed previously and could not cleanup.
  if (base::PathExists(version_path)) {
    brillo::DeletePathRecursively(version_path);
  }

  if (mkdir(version_path.value().c_str(), kComponentDirPerms) != 0) {
    PLOG(ERROR) << "Could not create directory for new component version.";
    return false;
  }

  if (!component->CopyTo(version_path)) {
    brillo::DeletePathRecursively(version_path);
    return false;
  }

  if (!base::ImportantFileWriter::WriteFileAtomically(version_hint_path,
                                                      version)) {
    brillo::DeletePathRecursively(version_path);
    LOG(ERROR) << "Failed to update current version hint file.";
    return false;
  }

  // Now delete the old component version, if there was one.
  if (have_old_version) {
    brillo::DeletePathRecursively(GetVersionPath(name, old_version_hint));
  }

  return true;
}

std::string ImageLoaderImpl::GetComponentVersion(const std::string& name) {
  if (!IsIdValid(name)) {
    return kBadResult;
  }

  base::FilePath component_path;
  if (!GetPathToCurrentComponentVersion(name, &component_path)) {
    return kBadResult;
  }

  std::unique_ptr<Component> component =
      Component::Create(component_path, config_.keys);
  if (!component)
    return kBadResult;

  return component->manifest().version();
}

bool ImageLoaderImpl::GetComponentMetadata(
    const std::string& name, std::map<std::string, std::string>* out_metadata) {
  if (!IsIdValid(name)) {
    return false;
  }

  base::FilePath component_path;
  if (!GetPathToCurrentComponentVersion(name, &component_path)) {
    return false;
  }

  std::unique_ptr<Component> component =
      Component::Create(component_path, config_.keys);
  if (!component)
    return false;

  *out_metadata = component->manifest().metadata();
  return true;
}

base::FilePath ImageLoaderImpl::GetLatestVersionFilePath(
    const std::string& component_name) {
  return GetComponentRoot(component_name).Append(kLatestVersionFile);
}

base::FilePath ImageLoaderImpl::GetVersionPath(
    const std::string& component_name, const std::string& version) {
  return GetComponentRoot(component_name).Append(version);
}

base::FilePath ImageLoaderImpl::GetComponentRoot(
    const std::string& component_name) {
  return config_.storage_dir.Append(component_name);
}

bool ImageLoaderImpl::GetPathToCurrentComponentVersion(
    const std::string& component_name, base::FilePath* result) {
  base::FilePath component_root(GetComponentRoot(component_name));
  base::FilePath latest_version_path = GetLatestVersionFilePath(component_name);

  // Check that the version file exists, otherwise the logging when
  // ReadFileToString fails confuses the crash reporting. If the file doesn't
  // exist, the component most likely isn't installed.
  if (!base::PathExists(latest_version_path)) {
    LOG(INFO) << "The latest-version file does not exist. Component "
              << component_name << " is probably not installed.";
    return false;
  }

  std::string latest_version;
  if (!base::ReadFileToStringWithMaxSize(latest_version_path, &latest_version,
                                         kMaximumLatestVersionSize)) {
    LOG(ERROR) << "Failed to read latest-version file.";
    return false;
  }

  *result = component_root.Append(latest_version);
  return true;
}

}  // namespace imageloader
