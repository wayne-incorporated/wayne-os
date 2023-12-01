// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_SETUP_ARC_SETUP_UTIL_H_
#define ARC_SETUP_ARC_SETUP_UTIL_H_

#include <sys/types.h>
#include <unistd.h>

#include <initializer_list>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/functional/callback.h>
#include <brillo/files/safe_fd.h>
#include <libsegmentation/feature_management.h>

#include "arc/setup/android_sdk_version.h"

namespace base {

class Environment;
class TimeDelta;

}  // namespace base

namespace arc {

constexpr bool kUseHoudini64 = USE_HOUDINI64;
constexpr bool kUseHoudini = USE_HOUDINI;
constexpr bool kUseNdkTranslation = USE_NDK_TRANSLATION;

// A class that provides mount(2) and umount(2) wrappers. They return true on
// success.
class ArcMounter {
 public:
  virtual ~ArcMounter() = default;

  virtual bool Mount(const std::string& source,
                     const base::FilePath& target,
                     const char* filesystem_type,
                     unsigned long mount_flags,  // NOLINT(runtime/int)
                     const char* data) = 0;

  virtual bool Remount(const base::FilePath& target_directory,
                       unsigned long mount_flags,  // NOLINT(runtime/int)
                       const char* data) = 0;

  virtual bool LoopMount(const std::string& source,
                         const base::FilePath& target,
                         unsigned long mount_flags) = 0;  // NOLINT(runtime/int)

  virtual bool BindMount(const base::FilePath& old_path,
                         const base::FilePath& new_path) = 0;

  virtual bool SharedMount(const base::FilePath& path) = 0;

  virtual bool Umount(const base::FilePath& path) = 0;

  virtual bool UmountIfExists(const base::FilePath& path) = 0;

  // Unmounts |path|, then frees the loop device for the |path|.
  virtual bool LoopUmount(const base::FilePath& path) = 0;

  virtual bool LoopUmountIfExists(const base::FilePath& path) = 0;
};

// A class that umounts a mountpoint when the mountpoint goes out of scope.
class ScopedMount {
 public:
  ScopedMount(const base::FilePath& path, ArcMounter* mounter, bool is_loop);
  ScopedMount(const ScopedMount&) = delete;
  ScopedMount& operator=(const ScopedMount&) = delete;

  ~ScopedMount();

  // Mounts |source| to |target| and returns a unique_ptr that umounts the
  // mountpoint when it goes out of scope.
  static std::unique_ptr<ScopedMount> CreateScopedMount(
      ArcMounter* mounter,
      const std::string& source,
      const base::FilePath& target,
      const char* filesystem_type,
      unsigned long mount_flags,  // NOLINT(runtime/int)
      const char* data);

  // Loopmounts |source| to |target| and returns a unique_ptr that umounts the
  // mountpoint when it goes out of scope.
  static std::unique_ptr<ScopedMount> CreateScopedLoopMount(
      ArcMounter* mounter,
      const std::string& source,
      const base::FilePath& target,
      unsigned long flags);  // NOLINT(runtime/int)

  // Bindmounts |old_path| to |new_path| and returns a unique_ptr that umounts
  // the mountpoint when it goes out of scope.
  static std::unique_ptr<ScopedMount> CreateScopedBindMount(
      ArcMounter* mounter,
      const base::FilePath& old_path,
      const base::FilePath& new_path);

 private:
  // Owned by caller.
  ArcMounter* const mounter_;
  const base::FilePath path_;
  const bool is_loop_;
};

// Resolves |path| to an absolute path that does not include symbolic links
// or the special .  or ..  directory entries.
base::FilePath Realpath(const base::FilePath& path);

// Changes the owner of the |path|. Returns true on success.
bool Chown(uid_t uid, gid_t gid, const base::FilePath& path);

// Changes SELinux context of the |path|. Returns true on success.
bool Chcon(const std::string& context, const base::FilePath& path);

// Creates the |path| with the |mode|, |uid|, and |gid|. Also creates parent
// directories of the |path| if they do not exist. Newly created parent
// directories will have 0755 (mode), caller's uid, and caller's gid.
// Returns true on success.
bool InstallDirectory(mode_t mode,
                      uid_t uid,
                      gid_t gid,
                      const base::FilePath& path);

// Creates |file_path| with |mode| and writes |content| to the file. If the
// file already exists, this function overwrites the existing one and sets its
// mode to |mode|. Returns true on success.
bool WriteToFile(const base::FilePath& file_path,
                 mode_t mode,
                 const std::string& content);

// Reads |prop_file_path| for an Android property with |prop_name|. If the
// property is found, stores its value in |out_prop| and returns true.
// Otherwise, returns false without updating |out_prop|.
bool GetPropertyFromFile(const base::FilePath& prop_file_path,
                         const std::string& prop_name,
                         std::string* out_prop);

// Reads |prop_file_path| and fills property map |out_properties|. Returns true
// if property file was correctly read and parsed.
bool GetPropertiesFromFile(const base::FilePath& prop_file_path,
                           std::map<std::string, std::string>* out_properties);

// Creates |file_path| with |mode|. If the file already exists, this function
// sets the file size to 0 and mode to |mode|. Returns true on success.
bool CreateOrTruncate(const base::FilePath& file_path, mode_t mode);

// Waits for all paths in |paths| to be available. Returns true if all the paths
// are found. If it times out, returns false. If |out_elapsed| is not |nullptr|,
// the function stores the time spent in the function in the variable.
bool WaitForPaths(std::initializer_list<base::FilePath> paths,
                  const base::TimeDelta& timeout,
                  base::TimeDelta* out_elapsed);

// Launches the command specified by |argv| and waits for the command to finish.
// Returns true if the command returns 0.
//
// WARNING: LaunchAndWait is *very* slow. Use this only when it's unavoidable.
// One LaunchAndWait call will take at least ~40ms on ARM Chromebooks because
// arc_setup is executed when the CPU is very busy and fork/exec takes time.
//
// WARNING: *Never* execute /bin/[u]mount with LaunchAndWait which may take
// ~200ms or more. Instead, use one of the mount/umount syscall wrappers above.
bool LaunchAndWait(const std::vector<std::string>& argv);

// Restores contexts of the |directories| and their contents recursively.
// Returns true on success.
bool RestoreconRecursively(const std::vector<base::FilePath>& directories);

// Restores contexts of the |paths|. Returns true on success.
bool Restorecon(const std::vector<base::FilePath>& paths);

// Generates a unique, 20-character hex string from |chromeos_user| and
// |salt| which can be used as Android's ro.boot.serialno and ro.serialno
// properties. Note that Android treats serialno in a case-insensitive manner.
std::string GenerateFakeSerialNumber(const std::string& chromeos_user,
                                     const std::string& salt);

// Gets an offset seed (>0) that can be passed to ArtContainer::PatchImage().
uint64_t GetArtCompilationOffsetSeed(const std::string& image_build_id,
                                     const std::string& salt);

// Clears |dir| by renaming it to a randomly-named temp directory in
// |android_data_old_dir|. Does nothing if |dir| does not exist or is not a
// directory. |android_data_old_dir| will be cleaned up by
// arc-stale-directory-remover kicked off by arc-booted signal.
bool MoveDirIntoDataOldDir(const base::FilePath& dir,
                           const base::FilePath& android_data_old_dir);

// Deletes files in |directory|, directory tree is kept to avoid recreating
// sub-directories.
bool DeleteFilesInDir(const base::FilePath& directory);

// Returns a mounter for production.
std::unique_ptr<ArcMounter> GetDefaultMounter();

// See OpenSafely() in arc_setup_util.cc.
base::ScopedFD OpenSafelyForTesting(const base::FilePath& path,
                                    int flags,
                                    mode_t mode);

// Reads |lsb_release_file_path| and returns the Chrome OS channel, or
// "unknown" in case of failures.
std::string GetChromeOsChannelFromFile(
    const base::FilePath& lsb_release_file_path);

// Reads the OCI container state from |path| and populates |out_container_pid|
// with the PID of the container and |out_rootfs| with the path to the root of
// the container.
bool GetOciContainerState(const base::FilePath& path,
                          pid_t* out_container_pid,
                          base::FilePath* out_rootfs);

// Returns true if the process with |pid| is alive or zombie.
bool IsProcessAlive(pid_t pid);

// Reads files in the vector and returns SHA1 hash of the files.
bool GetSha1HashOfFiles(const std::vector<base::FilePath>& files,
                        std::string* out_hash);

// Sets an extended attribute of the |path| to |value|.
bool SetXattr(const base::FilePath& path,
              const char* name,
              const std::string& value);

// Checks whether to clear entire android data directory before starting the
// container by comparing |system_sdk_version| from the current boot against
// |data_sdk_version| from the previous boot.
bool ShouldDeleteAndroidData(AndroidSdkVersion system_sdk_version,
                             AndroidSdkVersion data_sdk_version);

// A callback function that parses all lines and put key/value pair into the
// |out_properties|. Returns true in case line cannot be parsed in order to stop
// processing next lines.
bool FindAllProperties(std::map<std::string, std::string>* out_properties,
                       const std::string& line);

// Returns the user and group ids for a user.
bool GetUserId(const std::string& user, uid_t* user_id, gid_t* group_id);

// Make a copy of file |src_path| to |dest_path|.
// Use SafeFD to validate there is no symlink in the path.
bool SafeCopyFile(const base::FilePath& src_path,
                  brillo::SafeFD src_parent,
                  const base::FilePath& dest_path,
                  brillo::SafeFD dest_parent,
                  mode_t permissions = 0640,
                  uid_t uid = getuid(),
                  gid_t gid = getgid());

// Returns whether |image_path| points to an EROFS image file.
// Returns false if |image_path| is not an EROFS image file, or an error
// occurred while accessing it.
bool IsErofsImage(const base::FilePath& image_path);

// Generates a file called first stage fstab at |fstab_path| which is exported
// by crosvm to the guest via the device tree so the guest can read certain
// files in its init's first stage.
// |vendor_image_path| is used to check file system type of the vendor image.
// |cache_partition| indicates the device number of the disk for the cache
// partition to reside on. An empty string indicates that no disk is specified
// for cache partition (i.e. cache does not have a dedicated partition).
bool GenerateFirstStageFstab(const base::FilePath& combined_property_file_name,
                             const base::FilePath& fstab_path,
                             const base::FilePath& vendor_image_path,
                             const std::string& cache_partition);

// Filters camera profiles in |media_profile_xml| with the settings in
// |camera_test_config| and returns the filtered content.
std::optional<std::string> FilterMediaProfile(
    const base::FilePath& media_profile_xml,
    const base::FilePath& camera_test_config);

// Append Features coming from the libsegmentation library that Android must be
// aware of.
std::optional<std::string> AppendFeatureManagement(
    const base::FilePath& hardware_profile_xml,
    segmentation::FeatureManagement& feature_management);
}  // namespace arc

#endif  // ARC_SETUP_ARC_SETUP_UTIL_H_
