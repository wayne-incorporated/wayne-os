// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <getopt.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/types.h>

#include <algorithm>
#include <functional>
#include <iterator>
#include <memory>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>

#include <base/at_exit.h>
#include <base/check_op.h>
#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/functional/callback_forward.h>
#include <base/functional/callback_helpers.h>
#include <base/json/json_writer.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/process/launch.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <brillo/daemons/daemon.h>
#include <brillo/files/safe_fd.h>
#include <brillo/syslog_logging.h>
#include <libminijail.h>
#include <scoped_minijail.h>

#include <libcontainer/config.h>
#include <libcontainer/container.h>
#include <libcontainer/libcontainer.h>

#include "run_oci/container_config_parser.h"
#include "run_oci/container_options.h"
#include "run_oci/run_oci_utils.h"

namespace run_oci {

namespace {

constexpr char kRunContainersPath[] = "/run/containers";

constexpr char kProcSelfMountsPath[] = "/proc/self/mounts";

constexpr char kContainerPidFilename[] = "container.pid";
constexpr char kConfigJsonFilename[] = "config.json";
constexpr char kRunOciFilename[] = ".run_oci";
constexpr char kLogFilename[] = "log";

// PIDs can be up to 8 characters, plus the terminating NUL byte. Rounding it up
// to the next power-of-two.
constexpr size_t kMaxPidFileLength = 16;

const std::map<std::string, int> kSignalMap = {
#define SIGNAL_MAP_ENTRY(name) \
  { #name, SIG##name }
    SIGNAL_MAP_ENTRY(HUP),   SIGNAL_MAP_ENTRY(INT),    SIGNAL_MAP_ENTRY(QUIT),
    SIGNAL_MAP_ENTRY(ILL),   SIGNAL_MAP_ENTRY(TRAP),   SIGNAL_MAP_ENTRY(ABRT),
    SIGNAL_MAP_ENTRY(BUS),   SIGNAL_MAP_ENTRY(FPE),    SIGNAL_MAP_ENTRY(KILL),
    SIGNAL_MAP_ENTRY(USR1),  SIGNAL_MAP_ENTRY(SEGV),   SIGNAL_MAP_ENTRY(USR2),
    SIGNAL_MAP_ENTRY(PIPE),  SIGNAL_MAP_ENTRY(ALRM),   SIGNAL_MAP_ENTRY(TERM),
    SIGNAL_MAP_ENTRY(CLD),   SIGNAL_MAP_ENTRY(CHLD),   SIGNAL_MAP_ENTRY(CONT),
    SIGNAL_MAP_ENTRY(STOP),  SIGNAL_MAP_ENTRY(TSTP),   SIGNAL_MAP_ENTRY(TTIN),
    SIGNAL_MAP_ENTRY(TTOU),  SIGNAL_MAP_ENTRY(URG),    SIGNAL_MAP_ENTRY(XCPU),
    SIGNAL_MAP_ENTRY(XFSZ),  SIGNAL_MAP_ENTRY(VTALRM), SIGNAL_MAP_ENTRY(PROF),
    SIGNAL_MAP_ENTRY(WINCH), SIGNAL_MAP_ENTRY(POLL),   SIGNAL_MAP_ENTRY(IO),
    SIGNAL_MAP_ENTRY(PWR),   SIGNAL_MAP_ENTRY(SYS),
#undef SIGNAL_MAP_ENTRY
};

std::ostream& operator<<(std::ostream& o, const OciHook& hook) {
  o << "Hook{path=\"" << hook.path.value() << "\", args=[";
  bool first = true;
  for (const auto& arg : hook.args) {
    if (!first)
      o << ", ";
    first = false;
    o << arg;
  }
  o << "]}";
  return o;
}

// Converts a single UID map to a string.
std::string GetIdMapString(const OciLinuxNamespaceMapping& map) {
  std::ostringstream oss;
  oss << map.containerID << " " << map.hostID << " " << map.size;
  return oss.str();
}

// Converts an array of UID mappings given in |maps| to the string format the
// kernel understands and puts that string in |map_string_out|.
std::string IdStringFromMap(const std::vector<OciLinuxNamespaceMapping>& maps) {
  std::ostringstream oss;
  bool first = true;
  for (const auto& map : maps) {
    if (first)
      first = false;
    else
      oss << ",";
    oss << GetIdMapString(map);
  }
  return oss.str();
}

// Sanitize |flags| that can be used for filesystem of a given |type|.
int SanitizeFlags(const std::string& type, int flags) {
  int sanitized_flags = flags;
  // Right now, only sanitize sysfs and procfs.
  if (type != "sysfs" && type != "proc")
    return flags;

  // sysfs and proc should always have nodev, noexec, nosuid.
  // Warn the user if these weren't specified, then turn them on.
  sanitized_flags |= (MS_NODEV | MS_NOEXEC | MS_NOSUID);
  if (flags ^ sanitized_flags)
    LOG(WARNING) << "Sanitized mount of type " << type << ".";

  return sanitized_flags;
}

// Returns the path for |path| relative to |bundle_dir|.
base::FilePath MakeAbsoluteFilePathRelativeTo(const base::FilePath& bundle_dir,
                                              const base::FilePath& path) {
  if (path.IsAbsolute())
    return path;
  return bundle_dir.Append(path);
}

// Adds the mounts specified in |mounts| to |config_out|.
void ConfigureMounts(const std::vector<OciMount>& mounts,
                     const base::FilePath& bundle_dir,
                     uid_t uid,
                     gid_t gid,
                     container_config* config_out) {
  // Get all the mountpoints in the external mount namespace upfront. This will
  // be used in case we need to perform any remounts, in order to preserve
  // flags that won't be changing.
  std::vector<run_oci::Mountpoint> mountpoints = run_oci::GetMountpointsUnder(
      base::FilePath("/"), base::FilePath(kProcSelfMountsPath));

  // Sort the list of mountpoints. For calculating remount flags, we are
  // interested in the deepest mount a particular path is located.  Since this
  // is a tree structure, traversing the list of mounts in inverse lexicographic
  // order and stopping in the first mount that is a prefix of the path works.
  std::sort(mountpoints.begin(), mountpoints.end(),
            [](const run_oci::Mountpoint& a, const run_oci::Mountpoint& b) {
              return b.path < a.path;
            });

  for (const auto& mount : mounts) {
    int mount_flags, negated_mount_flags, bind_mount_flags,
        mount_propagation_flags;
    bool loopback;
    std::string verity_options;
    std::string options = ParseMountOptions(
        mount.options, &mount_flags, &negated_mount_flags, &bind_mount_flags,
        &mount_propagation_flags, &loopback, &verity_options);

    base::FilePath source = mount.source;
    bool new_mount = true;
    if (mount.type == "bind") {
      // libminijail disallows relative bind-mounts.
      source = MakeAbsoluteFilePathRelativeTo(bundle_dir, mount.source);
      new_mount = false;
    }

    // Loopback devices have to be mounted outside.
    bool mount_in_ns = !mount.performInIntermediateNamespace && !loopback;

    // Bind-mounts cannot adjust the mount flags in the same call to mount(2),
    // so in order to do so, an explicit remount is needed. In order to avoid
    // clobbering unnecessary flags, we try to grab them from the closest
    // original mount point.
    int original_flags = 0;
    if (!new_mount) {
      for (const auto& mountpoint : mountpoints) {
        if (!base::StartsWith(source.value(), mountpoint.path.value(),
                              base::CompareCase::SENSITIVE)) {
          continue;
        }
        original_flags = mountpoint.mountflags;
        break;
      }
    }
    int new_flags = (original_flags & ~negated_mount_flags) | mount_flags;

    if (new_mount) {
      // This is a brand new mount. We pass in all the arguments that were
      // provided in the config.
      mount_flags = SanitizeFlags(mount.type, mount_flags);
      container_config_add_mount(
          config_out, "mount", source.value().c_str(),
          mount.destination.value().c_str(), mount.type.c_str(),
          options.empty() ? nullptr : options.c_str(),
          verity_options.empty() ? nullptr : verity_options.c_str(),
          mount_flags, uid, gid, 0750, mount_in_ns, true /* create */,
          loopback);
    } else if (bind_mount_flags) {
      // Bind-mounts only get the MS_BIND and maybe MS_REC|MS_RDONLY mount
      // flags.
      container_config_add_mount(
          config_out, "mount", source.value().c_str(),
          mount.destination.value().c_str(), mount.type.c_str(),
          nullptr /* options */, nullptr /* verity_options */,
          bind_mount_flags | (new_flags & MS_RDONLY), uid, gid, 0750,
          mount_in_ns, true /* create */, false /* loopback */);
    }
    if (mount_propagation_flags) {
      // Mount propagation flags need to be updated separately from the original
      // mount. Only the destination is important.
      container_config_add_mount(
          config_out, "mount", "" /* source */,
          mount.destination.value().c_str(), "" /* type */,
          nullptr /* options */, nullptr /* verity_options */,
          mount_propagation_flags, uid, gid, 0750, mount_in_ns,
          false /* create */, false /* loopback */);
    }
    if (!new_mount && new_flags != original_flags) {
      // Adding MS_BIND to the MS_REMOUNT will make the kernel apply the new
      // flags to the mount itself and not the superblock. This makes the
      // operation work in unprivileged user namespaces, since the container is
      // only allowed to modify its copy of the mount and not the underlying
      // superblock.
      new_flags |= MS_REMOUNT | MS_BIND;
      container_config_add_mount(
          config_out, "mount", "" /* source */,
          mount.destination.value().c_str(), "" /* type */,
          nullptr /* options */, nullptr /* verity_options */, new_flags, uid,
          gid, 0750, mount_in_ns, false /* create */, false /* loopback */);
    }
  }
}

// Adds the devices specified in |devices| to |config_out|.
void ConfigureDevices(const std::vector<OciLinuxDevice>& devices,
                      container_config* config_out) {
  for (const auto& device : devices) {
    container_config_add_device(
        config_out, device.type.c_str()[0], device.path.value().c_str(),
        device.fileMode, device.dynamicMajor ? -1 : device.major,
        device.dynamicMinor ? -1 : device.minor, device.dynamicMajor,
        device.dynamicMinor, device.uid, device.gid,
        0,  // Cgroup permission are now in 'resources'.
        0, 0);
  }
}

// Adds the cgroup device permissions specified in |devices| to |config_out|.
void ConfigureCgroupDevices(const std::vector<OciLinuxCgroupDevice>& devices,
                            container_config* config_out) {
  for (const auto& device : devices) {
    bool read_set = device.access.find('r') != std::string::npos;
    bool write_set = device.access.find('w') != std::string::npos;
    bool make_set = device.access.find('m') != std::string::npos;
    container_config_add_cgroup_device(
        config_out, device.allow, device.type.c_str()[0], device.major,
        device.minor, read_set, write_set, make_set);
  }
}

// Fills the libcontainer container_config struct given in |config_out| by
// pulling the apropriate fields from the OCI configuration given in |oci|.
bool ContainerConfigFromOci(const OciConfig& oci,
                            const base::FilePath& bundle_dir,
                            const std::vector<std::string>& extra_args,
                            container_config* config_out) {
  // Process configuration
  container_config_config_root(config_out, bundle_dir.value().c_str());
  container_config_uid(config_out, oci.process.user.uid);
  container_config_gid(config_out, oci.process.user.gid);
  container_config_additional_gids(config_out,
                                   oci.process.user.additionalGids.data(),
                                   oci.process.user.additionalGids.size());
  base::FilePath root_dir =
      MakeAbsoluteFilePathRelativeTo(bundle_dir, oci.root.path);
  container_config_premounted_runfs(config_out, root_dir.value().c_str());

  std::vector<const char*> argv;
  for (const auto& arg : oci.process.args)
    argv.push_back(arg.c_str());
  for (const auto& arg : extra_args)
    argv.push_back(arg.c_str());
  container_config_program_argv(config_out, argv.data(), argv.size());

  std::vector<const char*> namespaces;
  for (const auto& ns : oci.linux_config.namespaces) {
    namespaces.push_back(ns.type.c_str());
  }
  container_config_namespaces(config_out, namespaces.data(), namespaces.size());

  if (container_config_has_namespace(config_out, "user")) {
    if (oci.linux_config.uidMappings.empty() ||
        oci.linux_config.gidMappings.empty()) {
      LOG(ERROR) << "User namespaces require at least one uid/gid mapping";
      return false;
    }

    std::string uid_maps = IdStringFromMap(oci.linux_config.uidMappings);
    container_config_uid_map(config_out, uid_maps.c_str());

    std::string gid_maps = IdStringFromMap(oci.linux_config.gidMappings);
    container_config_gid_map(config_out, gid_maps.c_str());
  }

  ConfigureMounts(oci.mounts, bundle_dir, oci.process.user.uid,
                  oci.process.user.gid, config_out);
  ConfigureDevices(oci.linux_config.devices, config_out);
  ConfigureCgroupDevices(oci.linux_config.resources.devices, config_out);

  for (const auto& limit : oci.process.rlimits) {
    if (container_config_add_rlimit(config_out, limit.type, limit.soft,
                                    limit.hard)) {
      return false;
    }
  }

  return true;
}

// Reads json configuration of a container from |config_path| and filles
// |oci_out| with the specified container configuration.
bool OciConfigFromFile(const base::FilePath& config_path,
                       const OciConfigPtr& oci_out) {
  brillo::SafeFD fd(OpenOciConfigSafely(config_path));
  if (!fd.is_valid())
    return false;

  auto result = fd.ReadContents();
  if (brillo::SafeFD::IsError(result.second)) {
    LOG(ERROR) << "Failed to read container " << config_path.value()
               << " with error " << static_cast<int>(result.second);
    return false;
  }

  if (!run_oci::ParseContainerConfig(
          std::string(result.first.begin(), result.first.end()), oci_out)) {
    LOG(ERROR) << "Failed to parse container config: " << config_path.value();
    return false;
  }

  return true;
}

// Appends additional mounts specified in |bind_mounts| to the configuration
// given in |config_out|.
bool AppendMounts(const BindMounts& bind_mounts, container_config* config_out) {
  for (const auto& mount : bind_mounts) {
    if (container_config_add_mount(
            config_out, "mount", mount.first.value().c_str(),
            mount.second.value().c_str(), "bind", nullptr /* data */,
            nullptr /* verity */, MS_MGC_VAL | MS_BIND, 0, 0, 0750,
            true /* mount_in_ns */, true /* create */, false /* loopback */)) {
      PLOG(ERROR) << "Failed to add mount of " << mount.first.value();
      return false;
    }
  }

  return true;
}

// Generates OCI-compliant, JSON-formatted container state. This is
// pretty-printed so that bash scripts can more easily grab the fields instead
// of having to parse the JSON blob.
std::string ContainerState(pid_t child_pid,
                           const std::string& container_id,
                           const base::FilePath& bundle_dir,
                           const base::FilePath& container_dir,
                           const std::string& status) {
  base::Value::Dict state;
  state.Set("ociVersion", base::Value("1.0"));
  state.Set("id", base::Value(container_id));
  state.Set("status", base::Value(status));
  state.Set("bundle",
            base::Value(base::MakeAbsoluteFilePath(bundle_dir).value()));
  state.Set("pid", base::Value(child_pid));
  base::Value::Dict annotations;
  annotations.Set(
      "org.chromium.run_oci.container_root",
      base::Value(base::MakeAbsoluteFilePath(container_dir).value()));
  state.Set("annotations", std::move(annotations));
  std::string state_json;
  if (!base::JSONWriter::WriteWithOptions(
          state, base::JSONWriter::OPTIONS_PRETTY_PRINT, &state_json)) {
    LOG(ERROR) << "Failed to serialize the container state";
    return std::string();
  }
  return state_json;
}

// Runs one hook.
bool RunOneHook(const OciHook& hook,
                const std::string& hook_type,
                const std::string& container_state) {
  base::LaunchOptions options;
  if (!hook.env.empty()) {
    options.clear_environment = true;
    options.environment = hook.env;
  }

  base::ScopedFD write_pipe_read_fd, write_pipe_write_fd;
  if (!run_oci::Pipe(&write_pipe_read_fd, &write_pipe_write_fd, 0)) {
    PLOG(ERROR) << "Bad write pipe";
    return false;
  }
  base::FileHandleMappingVector fds_to_remap{
      {write_pipe_read_fd.get(), STDIN_FILENO}, {STDERR_FILENO, STDERR_FILENO}};
  options.fds_to_remap = std::move(fds_to_remap);

  std::vector<std::string> args;
  if (hook.args.empty()) {
    args.push_back(hook.path.value());
  } else {
    args = hook.args;
    // Overwrite the first argument with the path since base::LaunchProcess does
    // not take an additional parameter for the executable name. Since the OCI
    // spec mandates that the path should be absolute, it's better to use that
    // rather than rely on whatever short name was passed in |args|.
    args[0] = hook.path.value();
  }

  DVLOG(1) << "Running " << hook_type << " " << hook;

  base::Process child = base::LaunchProcess(args, options);
  write_pipe_read_fd.reset();
  if (!base::WriteFileDescriptor(write_pipe_write_fd.get(), container_state)) {
    PLOG(ERROR) << "Failed to send container state";
  }
  write_pipe_write_fd.reset();
  int exit_code;
  if (!child.WaitForExitWithTimeout(hook.timeout, &exit_code)) {
    LOG(ERROR) << "Timeout exceeded running " << hook_type << " hook " << hook;
    if (!child.Terminate(0, true))
      LOG(ERROR) << "Failed to terminate " << hook_type << " hook " << hook;
    return false;
  }
  if (exit_code != 0) {
    LOG(ERROR) << hook_type << " hook " << hook << " exited with status "
               << exit_code;
    return false;
  }
  return true;
}

bool RunHooks(const std::vector<OciHook>& hooks,
              pid_t* child_pid,
              const std::string& container_id,
              const base::FilePath& bundle_dir,
              const base::FilePath& container_dir,
              const std::string& hook_stage,
              const std::string& status) {
  if (*child_pid == -1 && hook_stage != "precreate") {
    // If the child PID is not present, that means that the container failed to
    // run at least to a point where there was a PID at all. Hooks do not need
    // to be run in that case.
    return false;
  }
  bool success = true;
  std::string container_state = ContainerState(
      *child_pid, container_id, bundle_dir, container_dir, status);
  for (const auto& hook : hooks)
    success &= RunOneHook(hook, hook_stage, container_state);
  if (!success)
    LOG(WARNING) << "Error running " << hook_stage << " hooks";
  return success;
}

bool SaveChildPidAndRunHooks(const std::vector<OciHook>& hooks,
                             pid_t* child_pid,
                             const std::string& container_id,
                             const base::FilePath& bundle_dir,
                             const base::FilePath& container_dir,
                             const std::string& hook_stage,
                             const std::string& status,
                             pid_t container_pid) {
  *child_pid = container_pid;
  return RunHooks(hooks, child_pid, container_id, bundle_dir, container_dir,
                  hook_stage, status);
}

// Perform any pre-execve(2) setup of the process state, in the context of the
// container.
int SetupProcessState(void* payload) {
  const OciProcess* process = reinterpret_cast<const OciProcess*>(payload);
  if (!process->env.empty()) {
    if (clearenv() != 0) {
      PLOG(ERROR) << "Failed to clear environment";
      return -errno;
    }
    for (const auto& entry : process->env) {
      if (setenv(entry.first.c_str(), entry.second.c_str(), true) != 0) {
        PLOG(ERROR) << "Failed to set " << entry.first << "=" << entry.second;
        return -errno;
      }
    }
  }
  if (umask(process->umask) == -1) {
    PLOG(ERROR) << "Failed to set umask to " << process->umask;
    return -errno;
  }

  return 0;
}

void CleanUpContainer(const base::FilePath& container_dir) {
  std::vector<run_oci::Mountpoint> mountpoints = run_oci::GetMountpointsUnder(
      container_dir, base::FilePath(kProcSelfMountsPath));

  // Sort the list of mountpoints. Since this is a tree structure, unmounting
  // recursively can be achieved by traversing this list in inverse
  // lexicographic order.
  std::sort(mountpoints.begin(), mountpoints.end(),
            [](const run_oci::Mountpoint& a, const run_oci::Mountpoint& b) {
              return b.path < a.path;
            });
  for (const auto& mountpoint : mountpoints) {
    if (umount2(mountpoint.path.value().c_str(), MNT_DETACH))
      PLOG(ERROR) << "Failed to unmount " << mountpoint.path.value();
  }

  if (!base::DeletePathRecursively(container_dir)) {
    PLOG(ERROR) << "Failed to clean up the container directory "
                << container_dir.value();
  }
}

// Runs an OCI image with the configuration found at |bundle_dir|.
// If |detach_after_start| is true, a new directory under kRunContainersPath
// will be created to store the state of the container.
// If |detach_after_start| is true, blocks until the program specified in
// config.json exits, otherwise blocks until after the post-start hooks have
// finished.
// Returns -1 on error.
int RunOci(const base::FilePath& bundle_dir,
           const std::string& container_id,
           const ContainerOptions& container_options,
           bool detach_after_start) {
  LOG(INFO) << "Starting container " << container_id;

  base::FilePath container_dir;
  const base::FilePath container_config_file =
      bundle_dir.Append(kConfigJsonFilename);

  OciConfigPtr oci_config(new OciConfig());
  if (!OciConfigFromFile(container_config_file, oci_config))
    return -1;

  pid_t child_pid = -1;
  if (!oci_config->pre_create_hooks.empty()) {
    // Run the precreate hooks now.
    if (!RunHooks(oci_config->pre_create_hooks, &child_pid, container_id,
                  bundle_dir, container_dir, "precreate", "creating")) {
      LOG(ERROR) << "Error running precreate hooks";
      return -1;
    }
  }

  // Inject options passed in from the commandline.
  if (oci_config->linux_config.cgroupsPath.empty()) {
    // The OCI spec says that absolute paths for |cgroupsPath| are treated as
    // relative to the root of the cgroup hierarchy.
    oci_config->linux_config.cgroupsPath =
        base::FilePath("/" + container_options.cgroup_parent);
  }

  container_dir = base::FilePath(kRunContainersPath).Append(container_id);
  base::ScopedClosureRunner cleanup(
      base::BindOnce(CleanUpContainer, container_dir));
  // Not using base::CreateDirectory() since we want to error out when the
  // directory exists a priori.
  if (mkdir(container_dir.value().c_str(), 0755) != 0) {
    PLOG(ERROR) << "Failed to create the container directory";
    return -1;
  }

  // Create an empty file, just to tag this container as being
  // run_oci-managed.
  const base::FilePath tag_file = container_dir.Append(kRunOciFilename);
  if (base::WriteFile(tag_file, "", 0) != 0) {
    LOG(ERROR) << "Failed to create tag file: " << tag_file.value();
    return -1;
  }

  // Create a symlink to quickly be able to navigate to the root of the
  // container.
  base::FilePath rootfs_path =
      MakeAbsoluteFilePathRelativeTo(bundle_dir, oci_config->root.path);
  base::FilePath rootfs_symlink =
      container_dir.Append("mountpoints/container-root");
  if (!base::CreateDirectory(rootfs_symlink.DirName())) {
    PLOG(ERROR) << "Failed to create mountpoints directory";
    return -1;
  }
  if (!base::CreateSymbolicLink(rootfs_path, rootfs_symlink)) {
    PLOG(ERROR) << "Failed to create mountpoints/container-root symlink";
    return -1;
  }
  if (!container_options.log_file.empty() &&
      !base::CreateSymbolicLink(container_options.log_file,
                                container_dir.Append(kLogFilename))) {
    PLOG(ERROR) << "Failed to create log symlink";
  }

  bool needs_intermediate_mount_ns = false;
  for (const auto& mount : oci_config->mounts) {
    if (!mount.performInIntermediateNamespace)
      continue;
    needs_intermediate_mount_ns = true;
    break;
  }
  if (needs_intermediate_mount_ns) {
    if (!HasCapSysAdmin()) {
      PLOG(ERROR) << "Specifying 'performInIntermediateNamespace' for any "
                     "mount requires having the CAP_SYS_ADMIN capability";
      return -1;
    }
    ScopedMinijail jail(minijail_new());
    if (!jail) {
      PLOG(ERROR) << "Failed to create a minijail for the intermediate mount "
                     "namespace.";
      return -1;
    }
    minijail_namespace_vfs(jail.get());
    minijail_skip_remount_private(jail.get());
    minijail_enter(jail.get());

    DCHECK_EQ(oci_config->linux_config.rootfsPropagation &
                  ~(MS_SHARED | MS_SLAVE | MS_PRIVATE | MS_UNBINDABLE | MS_REC),
              0);
    // TODO(lhchavez): Also support rootfsPropagation for the
    // non-intermediate-namespace case.
    if (mount(nullptr, "/", nullptr, oci_config->linux_config.rootfsPropagation,
              nullptr) == -1) {
      PLOG(ERROR) << "Failed to set the root propagation flags";
      return -1;
    }
  }

  libcontainer::Config config;
  if (!ContainerConfigFromOci(*oci_config, bundle_dir,
                              container_options.extra_program_args,
                              config.get())) {
    PLOG(ERROR) << "Failed to create container from oci config.";
    return -1;
  }

  AppendMounts(container_options.bind_mounts, config.get());
  // Create a container based on the config.  The run_dir argument will be
  // unused as this container will be run in place where it was mounted.
  libcontainer::Container container(oci_config->hostname,
                                    base::FilePath("/unused"));

  // Close all open FDs in the container except stdio, so that we get unified
  // logs.
  const int inherited_fds[] = {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO};
  if (container_config_inherit_fds(config.get(), inherited_fds,
                                   std::size(inherited_fds))) {
    LOG(WARNING) << "Failed to inherit stdout/stderr.";
  }

  if (!oci_config->process.capabilities.empty()) {
    container_config_set_capmask(
        config.get(), oci_config->process.capabilities["effective"].to_ullong(),
        oci_config->process.capabilities.find("ambient") !=
            oci_config->process.capabilities.end());
  }

  if (!oci_config->process.selinuxLabel.empty()) {
    container_config_set_selinux_context(
        config.get(), oci_config->process.selinuxLabel.c_str());
  }

  // The OCI spec says that absolute paths for |cgroupsPath| must be treated as
  // relative to the cgroups mount point, and relative paths may be interepreted
  // to being relative to a runtime-determined point in the hierarchy. We choose
  // to interpret both cases as relative to the cgroups mount point for the time
  // being.
  std::string cgroup_parent = oci_config->linux_config.cgroupsPath.value();
  if (oci_config->linux_config.cgroupsPath.IsAbsolute())
    cgroup_parent = cgroup_parent.substr(1);
  if (!cgroup_parent.empty()) {
    container_config_set_cgroup_parent(config.get(), cgroup_parent.c_str(),
                                       container_config_get_uid(config.get()),
                                       container_config_get_gid(config.get()));
  }

  if (container_options.use_current_user) {
    OciLinuxNamespaceMapping single_map = {
        getuid(),  // hostID
        0,         // containerID
        1          // size
    };
    std::string map_string = GetIdMapString(single_map);
    container_config_uid_map(config.get(), map_string.c_str());
    container_config_gid_map(config.get(), map_string.c_str());
  }

  if (oci_config->linux_config.cpu.shares) {
    container_config_set_cpu_shares(config.get(),
                                    oci_config->linux_config.cpu.shares);
  }
  if (oci_config->linux_config.cpu.quota &&
      oci_config->linux_config.cpu.period) {
    container_config_set_cpu_cfs_params(config.get(),
                                        oci_config->linux_config.cpu.quota,
                                        oci_config->linux_config.cpu.period);
  }
  if (oci_config->linux_config.cpu.realtimeRuntime &&
      oci_config->linux_config.cpu.realtimePeriod) {
    container_config_set_cpu_rt_params(
        config.get(), oci_config->linux_config.cpu.realtimeRuntime,
        oci_config->linux_config.cpu.realtimePeriod);
  }

  container_config_set_core_sched(config.get(),
                                  oci_config->linux_config.coreSched);

  if (!oci_config->linux_config.altSyscall.empty()) {
    container_config_alt_syscall_table(
        config.get(), oci_config->linux_config.altSyscall.c_str());
  }

  if (oci_config->linux_config.skipSecurebits) {
    container_config_set_securebits_skip_mask(
        config.get(), oci_config->linux_config.skipSecurebits);
  }

  container_config_set_run_as_init(config.get(), container_options.run_as_init);

  // Prepare the post-stop hooks to be run. Note that we don't need to run them
  // if the |child_pid| is -1. Either the pre-start hooks or the call to
  // container_pid() will populate the value, and RunHooks() will simply refuse
  // to run if |child_pid| is -1, so we will always do the right thing.
  // The callback is run in the same stack, so std::cref() is safe.
  base::ScopedClosureRunner post_stop_hooks(base::BindOnce(
      base::IgnoreResult(&RunHooks), std::cref(oci_config->post_stop_hooks),
      base::Unretained(&child_pid), container_id, bundle_dir, container_dir,
      "poststop", "stopped"));

  if (!oci_config->pre_chroot_hooks.empty()) {
    config.AddHook(
        MINIJAIL_HOOK_EVENT_PRE_CHROOT,
        base::BindOnce(&SaveChildPidAndRunHooks,
                       std::cref(oci_config->pre_chroot_hooks),
                       base::Unretained(&child_pid), container_id, bundle_dir,
                       container_dir, "prechroot", "created"));
  }
  if (!oci_config->pre_start_hooks.empty()) {
    config.AddHook(
        MINIJAIL_HOOK_EVENT_PRE_EXECVE,
        base::BindOnce(&SaveChildPidAndRunHooks,
                       std::cref(oci_config->pre_start_hooks),
                       base::Unretained(&child_pid), container_id, bundle_dir,
                       container_dir, "prestart", "created"));
  }
  // This needs to run in the context of the container process.
  container_config_set_pre_execve_hook(config.get(), &SetupProcessState,
                                       &oci_config->process);

  int rc;
  rc = container_start(container.get(), config.get());
  if (rc) {
    errno = -rc;
    PLOG(ERROR) << "start failed: " << container_dir.value();
    return -1;
  }

  child_pid = container_pid(container.get());
  const base::FilePath container_pid_path =
      container_dir.Append(kContainerPidFilename);
  std::string child_pid_str = base::StringPrintf("%d\n", child_pid);
  if (base::WriteFile(container_pid_path, child_pid_str.c_str(),
                      child_pid_str.size()) != child_pid_str.size()) {
    PLOG(ERROR) << "Failed to write the container PID to "
                << container_pid_path.value();
    return -1;
  }

  // Create another symlink similar to mountpoints/container-root. Unlike
  // mountpoints/container-root, this one provides the view from inside the
  // container.
  base::FilePath procfs_path(base::StringPrintf("/proc/%d/root", child_pid));
  base::FilePath symlink_path = container_dir.Append("root");
  if (!base::CreateSymbolicLink(procfs_path, symlink_path)) {
    PLOG(ERROR) << "Failed to create root/ symlink";
    container_kill(container.get());
    return -1;
  }

  if (!RunHooks(oci_config->post_start_hooks, &child_pid, container_id,
                bundle_dir, container_dir, "poststart", "running")) {
    LOG(ERROR) << "Error running poststart hooks";
    container_kill(container.get());
    return -1;
  }

  LOG(INFO) << "Container " << container_id << " running";

  if (detach_after_start) {
    // The container has reached a steady state. We can now return and let the
    // container keep running. We don't want to run the post-stop hooks now, but
    // until the user actually deletes the container.
    post_stop_hooks.ReplaceClosure(base::DoNothing());
    cleanup.ReplaceClosure(base::DoNothing());
    return 0;
  }

  if (container_options.sigstop_when_ready)
    raise(SIGSTOP);

  return container_wait(container.get());
}

// If this invocation of run_oci is operating on a pre-existing container,
// attempt to perform the same log redirection that was performed in the initial
// start so that all the logging statements appear in the same file and are
// easily correlated.
bool RestoreLogRedirection(const std::string& container_id) {
  const base::FilePath container_dir =
      base::FilePath(kRunContainersPath).Append(container_id);

  const base::FilePath log_file = container_dir.Append(kLogFilename);
  if (!base::PathExists(log_file)) {
    // No redirection needed.
    return true;
  }
  return !run_oci::RedirectLoggingAndStdio(log_file);
}

bool GetContainerPID(const std::string& container_id, pid_t* pid_out) {
  const base::FilePath container_dir =
      base::FilePath(kRunContainersPath).Append(container_id);
  const base::FilePath container_pid_path =
      container_dir.Append(kContainerPidFilename);

  std::string container_pid_str;
  if (!base::ReadFileToStringWithMaxSize(container_pid_path, &container_pid_str,
                                         kMaxPidFileLength)) {
    PLOG(ERROR) << "Failed to read " << container_pid_path.value();
    return false;
  }

  int container_pid;
  if (!base::StringToInt(
          base::TrimWhitespaceASCII(container_pid_str, base::TRIM_ALL),
          &container_pid)) {
    LOG(ERROR) << "Failed to convert the container pid to a number: "
               << container_pid_str;
    return false;
  }

  if (!base::PathExists(container_dir.Append(kRunOciFilename))) {
    LOG(ERROR) << "Container " << container_id << " is not run_oci-managed";
    return false;
  }

  *pid_out = static_cast<pid_t>(container_pid);
  return true;
}

int OciKill(const std::string& container_id, int kill_signal) {
  RestoreLogRedirection(container_id);
  LOG(INFO) << "Sending signal " << kill_signal << " to container "
            << container_id;

  pid_t container_pid;
  if (!GetContainerPID(container_id, &container_pid))
    return -1;

  if (kill(container_pid, kill_signal) == -1) {
    PLOG(ERROR) << "Failed to send signal " << kill_signal;
    return -1;
  }

  return 0;
}

int OciDestroy(const base::FilePath& bundle_dir,
               const std::string& container_id) {
  RestoreLogRedirection(container_id);
  LOG(INFO) << "Destroying container " << container_id;

  const base::FilePath container_dir =
      base::FilePath(kRunContainersPath).Append(container_id);
  const base::FilePath container_config_file =
      bundle_dir.Append(kConfigJsonFilename);

  if (!base::PathExists(container_dir)) {
    LOG(INFO) << "Container " << container_id << " has already been destroyed";
    return 0;
  }

  pid_t container_pid;
  if (!GetContainerPID(container_id, &container_pid)) {
    LOG(INFO) << "Container " << container_id << " is not running. "
              << "Cleaning up the container directory.";
  } else {
    if (kill(container_pid, 0) == 0) {
      LOG(ERROR) << "Container " << container_id << " is still running.";
      return -1;
    } else if (errno != ESRCH) {
      PLOG(ERROR) << "The state of container " << container_id
                  << " is unknown.";
      return -1;
    }
  }

  OciConfigPtr oci_config(new OciConfig());
  if (!OciConfigFromFile(container_config_file, oci_config)) {
    return -1;
  }

  // We are committed to cleaning everything up now.
  RunHooks(oci_config->post_stop_hooks, &container_pid, container_id,
           bundle_dir, container_dir, "poststop", "stopped");
  CleanUpContainer(container_dir);

  LOG(INFO) << "Container " << container_id << " destroyed";

  return 0;
}

const struct option longopts[] = {
    {"bind_mount", required_argument, nullptr, 'b'},
    {"help", no_argument, nullptr, 'h'},
    {"cgroup_parent", required_argument, nullptr, 'p'},
    {"use_current_user", no_argument, nullptr, 'u'},
    {"signal", required_argument, nullptr, 'S'},
    {"container_path", required_argument, nullptr, 'c'},
    {"log_dir", required_argument, nullptr, 'l'},
    {"log_tag", required_argument, nullptr, 't'},
    {"sigstop_when_ready", no_argument, nullptr, 's'},
    {0, 0, 0, 0},
};

void print_help(const char* argv0) {
  printf(
      "usage: %1$s [OPTIONS] <command> <container id>\n"
      "Commands:\n"
      "  run     creates and runs the container in the foreground.\n"
      "          %1$s will remain alive until the container's\n"
      "          init process exits and all resources are freed.\n"
      "          Running a container in this way does not support\n"
      "          the 'kill' or 'destroy' commands\n"
      "  start   creates and runs the container in the background.\n"
      "          The container can then be torn down with the 'kill'\n"
      "          command, and resources freed with the 'delete' command.\n"
      "  kill    sends the specified signal to the container's init.\n"
      "          the post-stop hooks will not be run at this time.\n"
      "  destroy runs the post-stop hooks and releases all resources.\n"
      "          If the container is not running, it just releases all\n"
      "          resources.\n"
      "\n"
      "Global options:\n"
      "  -h, --help                     Print this message and exit.\n"
      "  -l, --log_dir=<PATH>           Write logging messages to a file\n"
      "                                 in <PATH> instead of syslog.\n"
      "                                 Also redirects hooks' stdout/stderr.\n"
      "  -t, --log_tag=<TAG>            Use <TAG> as the syslog tag.\n"
      "\n"
      "run/start:\n"
      "\n"
      "  %1$s {run,start} [OPTIONS] <container id> [-- <args>]\n"
      "\n"
      "Options for run and start:\n"
      "  -c, --container_path=<PATH>    The path of the container.\n"
      "                                 Defaults to $PWD.\n"
      "  -b, --bind_mount=<A>:<B>       Mount path A to B container.\n"
      "  -p, --cgroup_parent=<NAME>     Set parent cgroup for container.\n"
      "  -u, --use_current_user         Map the current user/group only.\n"
      "  -i, --dont_run_as_init         Do not run the command as init.\n"
      "\n"
      "Options for run:\n"
      "  -s, --sigstop_when_ready      raise SIGSTOP on container is ready.\n"
      "                                 For use with Upstart's 'expect stop'.\n"
      "\n"
      "kill:\n"
      "\n"
      "  %1$s kill [OPTIONS] <container id>\n"
      "\n"
      "Options for kill:\n"
      "  -S, --signal=<SIGNAL>          The signal to send to init.\n"
      "                                 Defaults to TERM.\n"
      "destroy:\n"
      "\n"
      "  %1$s destroy <container id>\n"
      "\n",
      argv0);
}

}  // namespace

}  // namespace run_oci

int main(int argc, char** argv) {
  base::AtExitManager exit_manager;

  run_oci::ContainerOptions container_options;
  base::FilePath bundle_dir = base::MakeAbsoluteFilePath(base::FilePath("."));
  int c;
  int kill_signal = SIGTERM;

  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogHeader |
                  brillo::kLogToStderrIfTty);

  base::FilePath log_dir;

  while ((c = getopt_long(argc, argv, "b:B:c:hp:s:S:uUl:", run_oci::longopts,
                          nullptr)) != -1) {
    switch (c) {
      case 'b': {
        std::istringstream ss(optarg);
        std::string outside_path;
        std::string inside_path;
        std::getline(ss, outside_path, ':');
        std::getline(ss, inside_path, ':');
        if (outside_path.empty() || inside_path.empty()) {
          run_oci::print_help(argv[0]);
          return -1;
        }
        container_options.bind_mounts.push_back(run_oci::BindMount(
            base::MakeAbsoluteFilePath(base::FilePath(outside_path)),
            base::FilePath(inside_path)));
        break;
      }
      case 'c':
        bundle_dir = base::MakeAbsoluteFilePath(base::FilePath(optarg));
        break;
      case 'u':
        container_options.use_current_user = true;
        break;
      case 'p':
        container_options.cgroup_parent = optarg;
        break;
      case 'S': {
        auto it = run_oci::kSignalMap.find(optarg);
        if (it == run_oci::kSignalMap.end()) {
          LOG(ERROR) << "Invalid signal name '" << optarg << "'";
          return -1;
        }
        kill_signal = it->second;
        break;
      }
      case 'i':
        container_options.run_as_init = false;
        break;
      case 'l':
        log_dir = base::FilePath(optarg);
        // Can't use base::MakeAbsoluteFilePath since |log_dir| might not yet
        // exist.
        if (!log_dir.IsAbsolute()) {
          base::FilePath current_directory;
          if (!base::GetCurrentDirectory(&current_directory)) {
            PLOG(ERROR) << "Failed to get current directory";
            return -1;
          }
          log_dir = current_directory.Append(log_dir);
        }
        break;
      case 's':
        container_options.sigstop_when_ready = true;
        break;
      case 't':
        container_options.log_tag = optarg;
        break;
      case 'h':
        run_oci::print_help(argv[0]);
        return 0;
      default:
        run_oci::print_help(argv[0]);
        return 1;
    }
  }

  if (optind >= argc) {
    LOG(ERROR) << "Command is required.";
    run_oci::print_help(argv[0]);
    return -1;
  }
  std::string command(argv[optind++]);

  if (optind >= argc) {
    LOG(ERROR) << "Container id is required.";
    run_oci::print_help(argv[0]);
    return -1;
  }
  std::string container_id(argv[optind++]);
  if (container_id.find(base::FilePath::kSeparators[0]) != std::string::npos) {
    LOG(ERROR) << "Container ID cannot contain path separators.";
    run_oci::print_help(argv[0]);
    return -1;
  }

  for (; optind < argc; optind++)
    container_options.extra_program_args.push_back(std::string(argv[optind]));

  std::unique_ptr<run_oci::SyslogStdioAdapter> syslog_stdio_adapter;
  if (!log_dir.empty()) {
    // If the user has specified a value for |log_dir|, ensure the directory,
    // create a unique(-ish) file and redirect logging and output to it.
    if (!base::DirectoryExists(log_dir)) {
      // Not using base::CreateDirectory() since we want to set more relaxed
      // permissions.
      if (mkdir(log_dir.value().c_str(), 0755) != 0) {
        PLOG(ERROR) << "Failed to create log directory '" << log_dir.value()
                    << "'";
        return -1;
      }
    }
    container_options.log_file = log_dir.Append(base::StringPrintf(
        "%s.%s", container_id.c_str(),
        brillo::GetTimeAsLogString(base::Time::Now()).c_str()));
    if (!run_oci::RedirectLoggingAndStdio(container_options.log_file))
      return -1;
  } else if (!container_options.log_tag.empty()) {
    // brillo::OpenLog can be called safely even after log operations have been
    // made before.
    brillo::OpenLog(container_options.log_tag.c_str(), true /*log_pid*/);

    syslog_stdio_adapter = run_oci::SyslogStdioAdapter::Create();
    if (!syslog_stdio_adapter) {
      LOG(ERROR) << "Failed to create the syslog stdio adapter";
      return -1;
    }
  }

  if (command == "run") {
    int result = run_oci::RunOci(bundle_dir, container_id, container_options,
                                 false /*detach_after_start*/);
    LOG(INFO) << "Container " << container_id << " finished";
    return result;
  } else if (command == "start") {
    return run_oci::RunOci(bundle_dir, container_id, container_options,
                           true /*detach_after_start*/);
  } else if (command == "kill") {
    return run_oci::OciKill(container_id, kill_signal);
  } else if (command == "destroy") {
    return run_oci::OciDestroy(bundle_dir, container_id);
  } else {
    LOG(ERROR) << "Unknown command '" << command << "'";
    run_oci::print_help(argv[0]);
    return -1;
  }
}
