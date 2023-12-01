// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "init/startup/stateful_mount.h"

#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/json/json_reader.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/values.h>
#include <brillo/blkdev_utils/lvm.h>
#include <brillo/blkdev_utils/storage_utils.h>
#include <brillo/files/file_util.h>
#include <brillo/process/process.h>
#include <brillo/key_value_store.h>
#include <brillo/secure_blob.h>
#include <metrics/bootstat.h>
#include <rootdev/rootdev.h>

#include "init/startup/constants.h"
#include "init/startup/flags.h"
#include "init/startup/mount_helper.h"
#include "init/startup/platform_impl.h"
#include "init/startup/security_manager.h"
#include "init/utils.h"

namespace {

constexpr char kQuota[] = "proc/sys/fs/quota";
constexpr char kExt4Features[] = "sys/fs/ext4/features";
constexpr char kReservedBlocksGID[] = "20119";
constexpr char kQuotaOpt[] = "quota";
constexpr char kQuotaProjectOpt[] = "project";
constexpr char kDumpe2fsStatefulLog[] = "run/dumpe2fs_stateful.log";
constexpr char kDirtyExpireCentisecs[] = "proc/sys/vm/dirty_expire_centisecs";

constexpr char kHiberman[] = "usr/sbin/hiberman";
constexpr char kHiberResumeInitLog[] = "run/hibernate/hiber-resume-init.log";
constexpr char kDevMapper[] = "dev/mapper";
constexpr char kUnencryptedRW[] = "unencrypted-rw";
constexpr char kDevImageRW[] = "dev-image-rw";

constexpr char kUpdateAvailable[] = ".update_available";
constexpr char kLabMachine[] = ".labmachine";

constexpr char kVar[] = "var";
constexpr char kNew[] = "_new";
constexpr char kOverlay[] = "_overlay";
constexpr char kDevImage[] = "dev_image";

constexpr char kVarLogAsan[] = "var/log/asan";
constexpr char kStatefulDevImage[] = "mnt/stateful_partition/dev_image";
constexpr char kUsrLocal[] = "usr/local";
constexpr char kDisableStatefulSecurityHardening[] =
    "usr/share/cros/startup/disable_stateful_security_hardening";
constexpr char kTmpPortage[] = "var/tmp/portage";
constexpr char kProcMounts[] = "proc/mounts";
constexpr char kMountOptionsLog[] = "var/log/mount_options.log";
const std::vector<const char*> kMountDirs = {"db/pkg", "lib/portage",
                                             "cache/dlc-images"};
const std::vector kDisableSecHardDirs = {kStatefulDevImage, kTmpPortage};

// TODO(asavery): update the check for removable devices to be
// more advanced, b/209476959
bool RemovableRootdev(const base::FilePath& path, int* ret) {
  base::FilePath removable("/sys/block");
  removable = removable.Append(path.BaseName());
  removable = removable.Append("removable");
  return utils::ReadFileToInt(removable, ret);
}

uint64_t GetDirtyExpireCentisecs(const base::FilePath& root) {
  std::string dirty_expire;
  uint64_t dirty_expire_centisecs = 0;
  base::FilePath centisecs_path = root.Append(kDirtyExpireCentisecs);
  if (!base::ReadFileToString(centisecs_path, &dirty_expire)) {
    PLOG(WARNING) << "Failed to read " << centisecs_path.value();
    return 0;
  }

  base::TrimWhitespaceASCII(dirty_expire, base::TRIM_ALL, &dirty_expire);
  if (!base::StringToUint64(dirty_expire, &dirty_expire_centisecs)) {
    PLOG(WARNING) << "Failed to parse contents of " << centisecs_path.value();
  }
  return dirty_expire_centisecs;
}

// TODO(asavery): Use ext2fs library directly instead since we only use
// a subset of the information provided, b/241965074.
bool Dumpe2fs(const base::FilePath& path,
              const std::vector<std::string>& args,
              std::string* info) {
  brillo::ProcessImpl dump;
  dump.AddArg("/sbin/dumpe2fs");
  dump.AddArg("-h");
  for (const std::string& arg : args) {
    dump.AddArg(arg);
  }
  dump.AddArg(path.value());

  if (info) {
    dump.RedirectUsingMemory(STDOUT_FILENO);
  }
  if (dump.Run() != 0) {
    PLOG(WARNING) << "dumpe2fs failed";
    return false;
  }
  if (info) {
    *info = dump.GetOutputString(STDOUT_FILENO);
  }
  return true;
}

bool IsFeatureEnabled(const std::string& fs_features,
                      const std::string& feature) {
  // Check if feature is already enabled.
  return fs_features.find(feature) != std::string::npos;
}

bool IsReservedGidSet(const std::string& state_dumpe2fs) {
  std::size_t rbg_pos = state_dumpe2fs.find("Reserved blocks gid");
  if (rbg_pos != std::string::npos) {
    std::size_t nwl_pos = state_dumpe2fs.find("\n", rbg_pos);
    std::string rbg = state_dumpe2fs.substr(rbg_pos, nwl_pos);
    if (rbg.find(kReservedBlocksGID) == std::string::npos) {
      return false;
    }
    return true;
  }
  return false;
}

void AppendOption(const std::string& fs_features,
                  std::vector<std::string>* sb_options,
                  const std::string& option_name) {
  if (!IsFeatureEnabled(fs_features, option_name)) {
    sb_options->push_back(option_name);
  }
}

// Get the partition number for the given key,
// e.g. "PARTITION_NUM_STATE". Fails with a `CHECK()` if any error occurs.
int GetPartitionNumFromImageVars(const base::Value& image_vars,
                                 base::StringPiece key) {
  const base::Value::Dict& dict = image_vars.GetDict();
  const std::string* value = dict.FindString(key);
  CHECK_NE(value, nullptr);
  int num = 0;
  CHECK(base::StringToInt(*value, &num));
  return num;
}

}  // namespace

namespace startup {

StatefulMount::StatefulMount(const Flags& flags,
                             const base::FilePath& root,
                             const base::FilePath& stateful,
                             Platform* platform,
                             std::unique_ptr<brillo::LogicalVolumeManager> lvm,
                             MountHelper* mount_helper)
    : flags_(flags),
      root_(root),
      stateful_(stateful),
      platform_(platform),
      lvm_(std::move(lvm)),
      mount_helper_(mount_helper) {}

bool StatefulMount::GetImageVars(base::FilePath json_file,
                                 std::string key,
                                 base::Value* vars) {
  std::string json_string;
  if (!base::ReadFileToString(json_file, &json_string)) {
    PLOG(ERROR) << "Unable to read json file: " << json_file;
    return false;
  }
  auto part_vars = base::JSONReader::ReadAndReturnValueWithError(
      json_string, base::JSON_PARSE_RFC);
  if (!part_vars.has_value()) {
    PLOG(ERROR) << "Failed to parse image variables.";
    return false;
  }
  if (!part_vars->is_dict()) {
    LOG(ERROR) << "Failed to read json file as a dictionary";
    return false;
  }

  base::Value::Dict* image_vars = part_vars->GetDict().FindDict(key);
  if (image_vars == nullptr) {
    LOG(ERROR) << "Failed to get image variables from " << json_file;
    return false;
  }
  *vars = base::Value(std::move(*image_vars));
  return true;
}

bool StatefulMount::IsQuotaEnabled() {
  base::FilePath quota = root_.Append(kQuota);
  return base::DirectoryExists(quota);
}

void StatefulMount::AppendQuotaFeaturesAndOptions(
    const std::string& fs_features,
    const std::string& state_dumpe2fs,
    std::vector<std::string>* sb_options,
    std::vector<std::string>* sb_features) {
  // Enable/disable quota feature.
  if (!IsReservedGidSet(state_dumpe2fs)) {
    // Add Android's AID_RESERVED_DISK to resgid.
    sb_features->push_back("-g");
    sb_features->push_back(kReservedBlocksGID);
  }

  if (IsQuotaEnabled()) {
    // Quota is enabled in the kernel, make sure that quota is enabled in
    // the filesystem
    if (!IsFeatureEnabled(fs_features, kQuotaOpt)) {
      sb_options->push_back(kQuotaOpt);
      sb_features->push_back("-Qusrquota,grpquota");
    }
    std::optional<bool> prjquota_sup = flags_.prjquota;
    bool prjquota = prjquota_sup.value_or(false);
    if (prjquota) {
      if (!IsFeatureEnabled(fs_features, kQuotaProjectOpt)) {
        sb_features->push_back("-Qprjquota");
      }
    } else {
      if (IsFeatureEnabled(fs_features, kQuotaProjectOpt)) {
        sb_features->push_back("-Q^prjquota");
      }
    }
  } else {
    // Quota is not enabled in the kernel, make sure that quota is disabled
    // in the filesystem.
    if (IsFeatureEnabled(fs_features, kQuotaOpt)) {
      sb_options->push_back("^quota");
      sb_features->push_back("-Q^usrquota,^grpquota,^prjquota");
    }
  }
}

void StatefulMount::EnableExt4Features() {
  std::vector<std::string> sb_features = GenerateExt4FeaturesWrapper();

  if (!sb_features.empty()) {
    brillo::ProcessImpl tune2fs;
    tune2fs.AddArg("/sbin/tune2fs");
    for (const std::string& arg : sb_features) {
      tune2fs.AddArg(arg);
    }
    tune2fs.AddArg(state_dev_.value());
    tune2fs.RedirectOutputToMemory(true);
    int status = tune2fs.Run();
    if (status != 0) {
      PLOG(ERROR) << "tune2fs failed with status: " << status;
    }
  }
}

std::vector<std::string> StatefulMount::GenerateExt4FeaturesWrapper() {
  std::string state_dumpe2fs;
  std::vector<std::string> args;
  if (!Dumpe2fs(state_dev_, args, &state_dumpe2fs)) {
    PLOG(ERROR) << "Failed dumpe2fs for stateful partition.";
    state_dumpe2fs = "";
  }
  return GenerateExt4Features(state_dumpe2fs);
}

std::vector<std::string> StatefulMount::GenerateExt4Features(
    const std::string state_dumpe2fs) {
  std::vector<std::string> sb_features;
  std::vector<std::string> sb_options;
  std::string feat;
  std::string fs_features;
  std::size_t feature_pos = state_dumpe2fs.find("Filesystem features:");
  if (feature_pos != std::string::npos) {
    std::size_t nl_pos = state_dumpe2fs.find("\n", feature_pos);
    fs_features = state_dumpe2fs.substr(feature_pos, nl_pos);
  }

  std::optional<bool> direncrypt = flags_.direncryption;
  bool direncryption = direncrypt.value_or(false);
  base::FilePath encryption = root_.Append(kExt4Features).Append("encryption");
  if (direncryption && base::PathExists(encryption)) {
    AppendOption(fs_features, &sb_options, "encrypt");
  }

  std::optional<bool> fsverity = flags_.fsverity;
  bool verity = fsverity.value_or(false);
  base::FilePath verity_file = root_.Append(kExt4Features).Append("verity");
  if (verity && base::PathExists(verity_file)) {
    AppendOption(fs_features, &sb_options, "verity");
  }

  AppendQuotaFeaturesAndOptions(fs_features, state_dumpe2fs, &sb_options,
                                &sb_features);

  if (!sb_features.empty() || !sb_options.empty()) {
    // Ensure to replay the journal first so it doesn't overwrite the flag.
    platform_->ReplayExt4Journal(state_dev_);

    if (!sb_options.empty()) {
      std::string opts = base::JoinString(sb_options, ",");
      sb_features.push_back("-O");
      sb_features.push_back(opts);
    }
  }

  return sb_features;
}

// Check to see if this a hibernate resume boot.
bool StatefulMount::HibernateResumeBoot() {
  base::FilePath hiberman_cmd = root_.Append(kHiberman);
  base::FilePath hiber_init_log = root_.Append(kHiberResumeInitLog);
  return (base::PathExists(hiberman_cmd) &&
          platform_->RunHiberman(hiber_init_log));
}

void StatefulMount::MountStateful() {
  base::FilePath root_dev;
  // Prepare to mount stateful partition.
  bool rootdev_ret = utils::GetRootDevice(&root_dev_type_, true);
  int removable = 0;
  if (!RemovableRootdev(root_dev_type_, &removable)) {
    PLOG(WARNING)
        << "Unable to read if rootdev is removable; assuming it's not";
  }
  std::string load_vars;
  if (removable == 1) {
    load_vars = "load_partition_vars";
  } else {
    load_vars = "load_base_vars";
  }

  base::Value image_vars;
  base::FilePath json_file = root_.Append("usr/sbin/partition_vars.json");
  if (!StatefulMount::GetImageVars(json_file, load_vars, &image_vars)) {
    return;
  }
  if (!image_vars.is_dict()) {
    PLOG(ERROR) << "Failed to parse dictionary from partition_vars.json";
    return;
  }
  const auto& image_vars_dict = image_vars.GetDict();

  bool status;
  int32_t stateful_mount_flags;
  std::string stateful_mount_opts;

  // Check if we are booted on physical media. rootdev will fail if we are in
  // an initramfs or tmpfs rootfs (ex, factory installer images. Note recovery
  // image also uses initramfs but it never reaches here). When using
  // initrd+tftpboot (some old netboot factory installer), ROOTDEV_TYPE will be
  // /dev/ram.
  if (rootdev_ret && root_dev_type_ != base::FilePath("/dev/ram")) {
    // Find our stateful partition mount point.
    stateful_mount_flags = kCommonMountFlags | MS_NOATIME;
    const int part_num_state =
        GetPartitionNumFromImageVars(image_vars, "PARTITION_NUM_STATE");
    const std::string* fs_form_state =
        image_vars_dict.FindString("FS_FORMAT_STATE");
    state_dev_ = brillo::AppendPartition(root_dev_type_, part_num_state);
    if (fs_form_state->compare("ext4") == 0) {
      int dirty_expire_centisecs = GetDirtyExpireCentisecs(root_);
      int commit_interval = dirty_expire_centisecs / 100;
      if (commit_interval != 0) {
        stateful_mount_opts = "commit=" + std::to_string(commit_interval);
        stateful_mount_opts.append(",discard");
      } else {
        LOG(INFO) << "Using default value for commit interval";
        stateful_mount_opts = "discard";
      }
    }

    std::optional<bool> lvm_stateful = flags_.lvm_stateful;
    bool lvm_enable = lvm_stateful.value_or(false);
    if (lvm_enable) {
      // Attempt to get a valid volume group name.
      bootstat_.LogEvent("pre-lvm-activation");
      auto pv = lvm_->GetPhysicalVolume(state_dev_);
      if (pv && pv->IsValid()) {
        volume_group_ = lvm_->GetVolumeGroup(*pv);
        if (volume_group_ && volume_group_->IsValid()) {
          // Check to see if this a hibernate resume boot. If so,
          // the image that will soon be resumed has active mounts
          // on the stateful LVs that must not be modified out from underneath
          // the hibernated kernel. Ask hiberman to activate the necessary
          // logical volumes and set up dm-snapshots on top of them to make a RW
          // system while leaving those LVs physically intact.
          if (HibernateResumeBoot()) {
            base::FilePath dev_mapper = root_.Append(kDevMapper);
            state_dev_ = dev_mapper.Append(kUnencryptedRW);
            dev_image_ = dev_mapper.Append(kDevImageRW);
          } else {
            auto lg =
                lvm_->GetLogicalVolume(volume_group_.value(), "unencrypted");
            lg->Activate();
            state_dev_ = root_.Append("dev")
                             .Append(volume_group_->GetName())
                             .Append("unencrypted");
            dev_image_ = root_.Append("dev")
                             .Append(volume_group_->GetName())
                             .Append("dev-image");
          }
        }
      }
      bootstat_.LogEvent("lvm-activation-complete");
    }

    EnableExt4Features();

    // Mount stateful partition from state_dev.
    if (!platform_->Mount(state_dev_, base::FilePath("/mnt/stateful_partition"),
                          fs_form_state->c_str(), stateful_mount_flags,
                          stateful_mount_opts)) {
      // Try to rebuild the stateful partition by clobber-state. (Not using fast
      // mode out of security consideration: the device might have gotten into
      // this state through power loss during dev mode transition).
      platform_->BootAlert("self_repair");

      platform_->ClobberLogRepair(state_dev_,
                                  "'Self-repair corrupted stateful partition'");

      std::vector<std::string> dump_args = {"-f"};
      std::string output;
      status = Dumpe2fs(state_dev_, dump_args, &output);
      base::FilePath log = root_.Append(kDumpe2fsStatefulLog);
      if (!status || !base::WriteFile(base::FilePath(log), output)) {
        PLOG(ERROR) << "Failed to write dumpe2fs output to "
                    << kDumpe2fsStatefulLog;
      }

      std::vector<std::string> crash_args{"--mount_failure",
                                          "--mount_device=stateful"};
      platform_->AddClobberCrashReport(crash_args);
      std::vector<std::string> argv{"keepimg"};
      platform_->Clobber(argv);
    }

    // Mount the OEM partition.
    // mount_or_fail isn't used since this partition only has a filesystem
    // on some boards.
    int32_t oem_flags = MS_RDONLY | kCommonMountFlags;
    const int part_num_oem =
        GetPartitionNumFromImageVars(image_vars, "PARTITION_NUM_OEM");
    const std::string* fs_form_oem =
        image_vars_dict.FindString("FS_FORMAT_OEM");
    const base::FilePath oem_dev =
        brillo::AppendPartition(root_dev_type_, part_num_oem);
    status = platform_->Mount(oem_dev, base::FilePath("/usr/share/oem"),
                              *fs_form_oem, oem_flags, "");
    if (!status) {
      PLOG(WARNING) << "mount of /usr/share/oem failed with code " << status;
    }
  }
}

void StatefulMount::SetStateDevForTest(const base::FilePath& dev) {
  state_dev_ = dev;
}

base::FilePath StatefulMount::GetStateDev() {
  return state_dev_;
}

base::FilePath StatefulMount::GetDevImage() {
  return dev_image_;
}

// Updates stateful partition if pending
// update is available.
// Returns true if there is no need to update or successful update.
bool StatefulMount::DevUpdateStatefulPartition(const std::string& args) {
  base::FilePath stateful_update_file = stateful_.Append(kUpdateAvailable);
  std::string stateful_update_args = args;
  if (stateful_update_args.empty()) {
    if (!base::ReadFileToString(stateful_update_file, &stateful_update_args)) {
      PLOG(WARNING) << "Failed to read from " << stateful_update_file.value();
      return true;
    }
    // The file often ends with a new line.
    base::TrimString(stateful_update_args, "\n", &stateful_update_args);
  }

  // To remain compatible with the prior update_stateful tarballs, expect
  // the "var_new" unpack location, but move it into the new "var_overlay"
  // target location.
  std::string var(kVar);
  std::string dev_image(kDevImage);
  base::FilePath var_new = stateful_.Append(var + kNew);
  base::FilePath developer_new = stateful_.Append(dev_image + kNew);
  base::FilePath developer_target = stateful_.Append(dev_image);
  base::FilePath var_target = stateful_.Append(var + kOverlay);
  std::vector<base::FilePath> paths_to_rm;

  // Only replace the developer and var_overlay directories if new replacements
  // are available.
  if (base::DirectoryExists(developer_new) && base::DirectoryExists(var_new)) {
    std::string update = "'Updating from " + developer_new.value() + " && " +
                         var_new.value() + ".'";
    platform_->ClobberLog(update);

    for (const std::string& path : {var, dev_image}) {
      base::FilePath path_new = stateful_.Append(path + kNew);
      base::FilePath path_target;
      if (path == "var") {
        path_target = stateful_.Append(path + kOverlay);
      } else {
        path_target = stateful_.Append(path);
      }
      if (!brillo::DeletePathRecursively(path_target)) {
        PLOG(WARNING) << "Failed to delete " << path_target.value();
      }

      if (!base::CreateDirectory(path_target)) {
        PLOG(WARNING) << "Failed to create " << path_target.value();
      }

      if (!base::SetPosixFilePermissions(path_target, 0755)) {
        PLOG(WARNING) << "chmod failed for " << path_target.value();
      }

      base::FileEnumerator enumerator(path_new, false /* recursive */,
                                      base::FileEnumerator::FILES |
                                          base::FileEnumerator::DIRECTORIES |
                                          base::FileEnumerator::SHOW_SYM_LINKS);

      for (base::FilePath fd = enumerator.Next(); !fd.empty();
           fd = enumerator.Next()) {
        if (!base::Move(fd, path_target.Append(fd.BaseName()))) {
          PLOG(WARNING) << "Failed to copy " << fd.value() << " to "
                        << path_target.value();
        }
      }
      paths_to_rm.push_back(path_new);
    }
    platform_->RemoveInBackground(paths_to_rm);
  } else {
    std::string update = "'Stateful update did not find " +
                         developer_new.value() + " & " + var_new.value() +
                         ".'\n'Keeping old development tools.'";
    platform_->ClobberLog(update);
  }

  // Check for clobber.
  if (stateful_update_args.compare("clobber") == 0) {
    base::FilePath preserve_dir = stateful_.Append("unencrypted/preserve");

    // Find everything in stateful and delete it, except for protected paths,
    // and non-empty directories. The non-empty directories contain protected
    // content or they would already be empty from depth first traversal.
    std::vector<base::FilePath> preserved_paths = {
        stateful_.Append(kLabMachine), developer_target, var_target,
        preserve_dir};
    base::FileEnumerator enumerator(stateful_, true,
                                    base::FileEnumerator::FILES |
                                        base::FileEnumerator::DIRECTORIES |
                                        base::FileEnumerator::SHOW_SYM_LINKS);
    for (auto path = enumerator.Next(); !path.empty();
         path = enumerator.Next()) {
      bool preserve = false;
      for (auto& preserved_path : preserved_paths) {
        if (path == preserved_path || preserved_path.IsParent(path) ||
            path.IsParent(preserved_path)) {
          preserve = true;
          break;
        }
      }

      if (!preserve) {
        if (base::DirectoryExists(path)) {
          brillo::DeletePathRecursively(path);
        } else {
          brillo::DeleteFile(path);
        }
      }
    }
    // Let's really be done before coming back.
    sync();
  }

  std::vector<base::FilePath> rm_paths{stateful_update_file};
  platform_->RemoveInBackground(rm_paths);

  return true;
}

// Gather logs.
void StatefulMount::DevGatherLogs(const base::FilePath& base_dir) {
  // For dev/test images, if .gatherme presents, copy files listed in .gatherme
  // to /mnt/stateful_partition/unencrypted/prior_logs.
  base::FilePath lab_preserve_logs = stateful_.Append(".gatherme");
  base::FilePath prior_log_dir = stateful_.Append("unencrypted/prior_logs");
  std::string log_path;

  if (!base::PathExists(lab_preserve_logs)) {
    return;
  }

  std::string files;
  base::ReadFileToString(lab_preserve_logs, &files);
  std::vector<std::string> split_files = base::SplitString(
      files, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  for (std::string log_path : split_files) {
    if (log_path.find("#") != std::string::npos) {
      continue;
    }
    base::FilePath log(log_path);
    if (base::DirectoryExists(log)) {
      if (!base::CopyDirectory(log, prior_log_dir, true)) {
        PLOG(WARNING) << "Failed to copy directory " << log_path;
      }
    } else {
      if (!base::CopyFile(log, prior_log_dir.Append(log.BaseName()))) {
        PLOG(WARNING) << "Failed to copy file " << log_path;
      }
    }
  }

  if (!brillo::DeleteFile(lab_preserve_logs)) {
    PLOG(WARNING) << "Failed to delete file: " << lab_preserve_logs;
  }
}

void StatefulMount::DevMountPackages(const base::FilePath& device) {
  // Set up the logging dir that ASAN compiled programs will write to. We want
  // any privileged account to be able to write here so unittests need not worry
  // about setting things up ahead of time. See crbug.com/453579 for details.
  base::FilePath asan_dir = root_.Append(kVarLogAsan);
  base::File::Error error;
  if (!base::CreateDirectoryAndGetError(asan_dir, &error)) {
    PLOG(WARNING) << "Unable to create /var/log/asan directory, error code: "
                  << error;
  }
  if (chmod(asan_dir.value().c_str(), 01777) != 0) {
    PLOG(WARNING) << "Set permissions failed for /var/log/asan";
  }

  // Capture a snapshot of "normal" mount state here, for auditability,
  // before we start applying devmode-specific changes.
  std::string mount_contents;
  base::FilePath proc_mounts = root_.Append(kProcMounts);
  if (!base::ReadFileToString(proc_mounts, &mount_contents)) {
    PLOG(ERROR) << "Reading from " << proc_mounts.value() << " failed.";
  }

  base::FilePath mount_options = root_.Append(kMountOptionsLog);
  if (!base::WriteFile(mount_options, mount_contents)) {
    PLOG(ERROR) << "Writing " << proc_mounts.value()
                << "to mount_options.log failed.";
  }

  // Create dev_image directory in base images in developer mode.
  base::FilePath stateful_dev = root_.Append(kStatefulDevImage);
  if (!base::DirectoryExists(stateful_dev)) {
    if (!base::CreateDirectory(stateful_dev)) {
      PLOG(ERROR) << "Failed to create " << stateful_dev.value();
    }
    if (!base::SetPosixFilePermissions(stateful_dev, 0755)) {
      PLOG(ERROR) << "Failed to set permissions for " << stateful_dev.value();
    }
  }

  // Mount the dev image if there is a separate device available.
  if (!device.empty()) {
    if (volume_group_ && volume_group_->IsValid()) {
      auto lg = lvm_->GetLogicalVolume(volume_group_.value(), "unencrypted");
      lg->Activate();
      platform_->Mount(device, stateful_dev, "",
                       MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_NOATIME,
                       "discard");
    }
  }

  // Checks and updates stateful partition.
  DevUpdateStatefulPartition("");

  // Mount and then remount to enable exec/suid.
  base::FilePath usrlocal = root_.Append(kUsrLocal);
  mount_helper_->MountOrFail(stateful_dev, usrlocal, "", MS_BIND, "");
  if (!platform_->Mount(base::FilePath(""), usrlocal, "", MS_REMOUNT, "")) {
    PLOG(WARNING) << "Failed to remount " << usrlocal.value();
  }

  base::FilePath disable_state_sec_hard =
      root_.Append(kDisableStatefulSecurityHardening);
  if (!base::PathExists(disable_state_sec_hard)) {
    // Add exceptions to allow symlink traversal and opening of FIFOs in the
    // dev_image subtree.
    for (const auto dir : kDisableSecHardDirs) {
      base::FilePath path = root_.Append(dir);
      if (!base::DirectoryExists(path)) {
        if (!base::CreateDirectory(path)) {
          PLOG(ERROR) << "Failed to create " << path.value();
        }
        if (!base::SetPosixFilePermissions(path, 0755)) {
          PLOG(ERROR) << "Failed to set permissions for " << path.value();
        }
      }
      AllowSymlink(root_, path.value());
      AllowFifo(root_, path.value());
    }
  }

  // Set up /var elements needed for deploying packages.
  base::FilePath base = stateful_.Append("var_overlay");
  if (base::DirectoryExists(base)) {
    for (const auto dir : kMountDirs) {
      base::FilePath full = base.Append(dir);
      if (!base::DirectoryExists(full)) {
        continue;
      }
      base::FilePath dest = root_.Append(kVar).Append(dir);
      if (!base::PathExists(dest)) {
        LOG(WARNING) << "Path does not exists, can not mount: " << dest.value();
        continue;
      }
      mount_helper_->MountOrFail(full, dest, "", MS_BIND, "");
    }
  }
}

}  // namespace startup
