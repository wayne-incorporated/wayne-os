// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "run_oci/container_config_parser.h"

#include <linux/securebits.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <unistd.h>

#include <map>
#include <optional>
#include <regex>  // NOLINT(build/c++11)
#include <string>
#include <utility>
#include <vector>

#include <base/json/json_reader.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/values.h>

namespace run_oci {

namespace {

// Gets an integer from the given dictionary.
template <typename T>
bool ParseIntFromDict(const base::Value::Dict& dict,
                      const char* name,
                      T* val_out) {
  std::optional<double> double_val = dict.FindDouble(name);
  if (!double_val.has_value()) {
    return false;
  }
  *val_out = static_cast<T>(*double_val);
  return true;
}

// Parse a list-type Value structure as vector of integers.
template <typename T>
bool ParseIntList(const base::Value::List& list_val, std::vector<T>* val_out) {
  for (const base::Value& entry : list_val) {
    if (!entry.is_double() && !entry.is_int()) {
      return false;
    }
    val_out->emplace_back(static_cast<T>(entry.GetDouble()));
  }
  return true;
}

// Parses basic platform configuration.
bool ParsePlatformConfig(const base::Value::Dict& config_root_dict,
                         OciConfigPtr const& config_out) {
  // |platform_dict| stays owned by |config_root_dict|
  const base::Value::Dict* platform_dict =
      config_root_dict.FindDict("platform");
  if (!platform_dict) {
    LOG(ERROR) << "Fail to parse platform dictionary from config";
    return false;
  }

  const std::string* os = platform_dict->FindString("os");
  if (!os) {
    return false;
  }
  config_out->platform.os = *os;

  const std::string* arch = platform_dict->FindString("arch");
  if (!arch) {
    return false;
  }
  config_out->platform.arch = *arch;

  return true;
}

// Parses root fs info.
bool ParseRootFileSystemConfig(const base::Value::Dict& config_root_dict,
                               OciConfigPtr const& config_out) {
  // |rootfs_dict| stays owned by |config_root_dict|
  const base::Value::Dict* rootfs_dict = config_root_dict.FindDict("root");
  if (!rootfs_dict) {
    LOG(ERROR) << "Fail to parse rootfs dictionary from config";
    return false;
  }
  const std::string* path = rootfs_dict->FindString("path");
  if (!path) {
    LOG(ERROR) << "Fail to get rootfs path from config";
    return false;
  }
  config_out->root.path = base::FilePath(*path);
  std::optional<bool> read_only = rootfs_dict->FindBool("readonly");
  if (read_only.has_value())
    config_out->root.readonly = *read_only;
  return true;
}

// Fills |config_out| with information about the capability sets in the
// container.
bool ParseCapabilitiesConfig(const base::Value::Dict& capabilities_dict,
                             std::map<std::string, CapSet>* config_out) {
  constexpr const char* kCapabilitySetNames[] = {
      "effective", "bounding", "inheritable", "permitted", "ambient"};
  const std::string kAmbientCapabilitySetName = "ambient";

  CapSet caps_superset;
  for (const char* set_name : kCapabilitySetNames) {
    // |capset_list| stays owned by |capabilities_dict|.
    const base::Value::List* capset_list = capabilities_dict.FindList(set_name);
    if (!capset_list)
      continue;
    CapSet caps;
    cap_value_t cap_value;
    for (const auto& cap_name_value : *capset_list) {
      if (!cap_name_value.is_string()) {
        LOG(ERROR) << "Capability list " << set_name
                   << " contains a non-string";
        return false;
      }
      std::string cap_name = cap_name_value.GetString();
      if (cap_from_name(cap_name.c_str(), &cap_value) == -1) {
        LOG(ERROR) << "Unrecognized capability name: " << cap_name;
        return false;
      }
      caps[cap_value] = true;
    }
    (*config_out)[set_name] = caps;
    caps_superset = caps;
  }

  // We currently only support sets that are identical, except that ambient is
  // optional.
  for (const char* set_name : kCapabilitySetNames) {
    auto it = config_out->find(set_name);
    if (it == config_out->end() && set_name == kAmbientCapabilitySetName) {
      // Ambient capabilities are optional.
      continue;
    }
    if (it == config_out->end()) {
      LOG(ERROR)
          << "If capabilities are set, all capability sets should be present";
      return false;
    }
    if (it->second != caps_superset) {
      LOG(ERROR)
          << "If capabilities are set, all capability sets should be identical";
      return false;
    }
  }

  return true;
}

const std::map<std::string, int> kRlimitMap = {
#define RLIMIT_MAP_ENTRY(limit) \
  { "RLIMIT_" #limit, RLIMIT_##limit }
    RLIMIT_MAP_ENTRY(CPU),      RLIMIT_MAP_ENTRY(FSIZE),
    RLIMIT_MAP_ENTRY(DATA),     RLIMIT_MAP_ENTRY(STACK),
    RLIMIT_MAP_ENTRY(CORE),     RLIMIT_MAP_ENTRY(RSS),
    RLIMIT_MAP_ENTRY(NPROC),    RLIMIT_MAP_ENTRY(NOFILE),
    RLIMIT_MAP_ENTRY(MEMLOCK),  RLIMIT_MAP_ENTRY(AS),
    RLIMIT_MAP_ENTRY(LOCKS),    RLIMIT_MAP_ENTRY(SIGPENDING),
    RLIMIT_MAP_ENTRY(MSGQUEUE), RLIMIT_MAP_ENTRY(NICE),
    RLIMIT_MAP_ENTRY(RTPRIO),   RLIMIT_MAP_ENTRY(RTTIME),
#undef RLIMIT_MAP_ENTRY
};

// Fills |config_out| with information about the capability sets in the
// container.
bool ParseRlimitsConfig(const base::Value::List& rlimits_list,
                        std::vector<OciProcessRlimit>* rlimits_out) {
  size_t num_limits = rlimits_list.size();
  for (size_t i = 0; i < num_limits; ++i) {
    if (!rlimits_list[i].is_dict()) {
      LOG(ERROR) << "Fail to get rlimit item " << i;
      return false;
    }
    const base::Value::Dict& rlimits_dict = rlimits_list[i].GetDict();

    const std::string* rlimit_name = rlimits_dict.FindString("type");
    if (!rlimit_name) {
      LOG(ERROR) << "Fail to get type of rlimit " << i;
      return false;
    }
    const auto it = kRlimitMap.find(*rlimit_name);
    if (it == kRlimitMap.end()) {
      LOG(ERROR) << "Unrecognized rlimit name: " << *rlimit_name;
      return false;
    }

    OciProcessRlimit limit;
    limit.type = it->second;
    if (!ParseIntFromDict(rlimits_dict, "hard", &limit.hard)) {
      LOG(ERROR) << "Fail to get hard limit of rlimit " << i;
      return false;
    }
    if (!ParseIntFromDict(rlimits_dict, "soft", &limit.soft)) {
      LOG(ERROR) << "Fail to get soft limit of rlimit " << i;
      return false;
    }
    rlimits_out->push_back(limit);
  }

  return true;
}

// Fills |config_out| with information about the main process to run in the
// container and the user it should be run as.
bool ParseProcessConfig(const base::Value::Dict& config_root_dict,
                        OciConfigPtr const& config_out) {
  // |process_dict| stays owned by |config_root_dict|
  const base::Value::Dict* process_dict = config_root_dict.FindDict("process");
  if (!process_dict) {
    LOG(ERROR) << "Fail to get main process from config";
    return false;
  }
  std::optional<bool> terminal = process_dict->FindBool("terminal");
  if (terminal.has_value())
    config_out->process.terminal = *terminal;
  // |user_dict| stays owned by |process_dict|
  const base::Value::Dict* user_dict = process_dict->FindDict("user");
  if (!user_dict) {
    LOG(ERROR) << "Failed to get user info from config";
    return false;
  }
  if (!ParseIntFromDict(*user_dict, "uid", &config_out->process.user.uid))
    return false;
  if (!ParseIntFromDict(*user_dict, "gid", &config_out->process.user.gid))
    return false;

  // If additionalGids field is specified, parse it as a valid list of integers.
  const base::Value::List* list_val = user_dict->FindList("additionalGids");
  if (list_val &&
      !ParseIntList(*list_val, &config_out->process.user.additionalGids)) {
    LOG(ERROR) << "Invalid process.user.additionalGids";
    return false;
  }

  // |args_list| stays owned by |process_dict|
  const base::Value::List* args_list = process_dict->FindList("args");
  if (!args_list) {
    LOG(ERROR) << "Fail to get main process args from config";
    return false;
  }
  for (const auto& arg : *args_list) {
    if (!arg.is_string()) {
      LOG(ERROR) << "Fail to get process args from config";
      return false;
    }
    config_out->process.args.push_back(arg.GetString());
  }
  // |env_list| stays owned by |process_dict|
  const base::Value::List* env_list = process_dict->FindList("env");
  if (env_list) {
    for (const auto& env_value : *env_list) {
      if (!env_value.is_string()) {
        LOG(ERROR) << "Fail to get process env from config";
        return false;
      }
      const std::string& env = env_value.GetString();
      std::vector<std::string> kvp = base::SplitString(
          env, "=", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
      if (kvp.size() != 2) {
        LOG(ERROR) << "Fail to parse env \"" << env
                   << "\". Must be in name=value format.";
        return false;
      }
      config_out->process.env.insert(std::make_pair(kvp[0], kvp[1]));
    }
  }
  const std::string* path = process_dict->FindString("cwd");
  if (!path) {
    LOG(ERROR) << "failed to get cwd of process";
    return false;
  }
  config_out->process.cwd = base::FilePath(*path);
  std::optional<int> umask_int = process_dict->FindInt("umask");
  if (umask_int.has_value())
    config_out->process.umask = static_cast<mode_t>(*umask_int);
  else
    config_out->process.umask = 0022;  // Optional

  // selinuxLabel is optional.
  const std::string* selinux_label = process_dict->FindString("selinuxLabel");
  if (selinux_label)
    config_out->process.selinuxLabel = *selinux_label;
  // |capabilities_dict| stays owned by |process_dict|
  const base::Value::Dict* capabilities_dict =
      process_dict->FindDict("capabilities");
  if (capabilities_dict) {
    if (!ParseCapabilitiesConfig(*capabilities_dict,
                                 &config_out->process.capabilities)) {
      return false;
    }
  }

  // |rlimit_list| stays owned by |process_dict|
  const base::Value::List* rlimits_list = process_dict->FindList("rlimits");
  if (rlimits_list) {
    if (!ParseRlimitsConfig(*rlimits_list, &config_out->process.rlimits)) {
      return false;
    }
  }

  return true;
}

// Parses the 'mounts' field.  The necessary mounts for running the container
// are specified here.
bool ParseMounts(const base::Value::Dict& config_root_dict,
                 OciConfigPtr const& config_out) {
  // |config_mounts_list| stays owned by |config_root_dict|
  const base::Value::List* config_mounts_list =
      config_root_dict.FindList("mounts");
  if (!config_mounts_list) {
    LOG(ERROR) << "Fail to get mounts from config dictionary";
    return false;
  }

  for (size_t i = 0; i < config_mounts_list->size(); ++i) {
    if (!(*config_mounts_list)[i].is_dict()) {
      LOG(ERROR) << "Fail to get mount item " << i;
      return false;
    }
    const base::Value::Dict& mount_dict = (*config_mounts_list)[i].GetDict();
    OciMount mount;
    const std::string* path = mount_dict.FindString("destination");
    if (!path) {
      LOG(ERROR) << "Fail to get mount path for mount " << i;
      return false;
    }
    mount.destination = base::FilePath(*path);
    const std::string* type = mount_dict.FindString("type");
    if (!type) {
      LOG(ERROR) << "Fail to get mount type for mount " << i;
      return false;
    }
    mount.type = *type;
    const std::string* source = mount_dict.FindString("source");
    if (!source) {
      LOG(ERROR) << "Fail to get mount source for mount " << i;
      return false;
    }
    mount.source = base::FilePath(*source);
    std::optional<bool> intermediate_namespace =
        mount_dict.FindBool("performInIntermediateNamespace");
    mount.performInIntermediateNamespace =
        intermediate_namespace.value_or(false);

    // |options| are owned by |mount_dict|
    const base::Value::List* options = mount_dict.FindList("options");
    if (options) {
      for (size_t j = 0; j < options->size(); ++j) {
        const base::Value& this_opt = (*options)[j];
        if (!this_opt.is_string()) {
          LOG(ERROR) << "Fail to get option " << j << " from mount options";
          return false;
        }
        mount.options.push_back(this_opt.GetString());
      }
    }

    config_out->mounts.push_back(mount);
  }
  return true;
}

// Parses the linux resource list
bool ParseResources(const base::Value::Dict& resources_dict,
                    OciLinuxResources* resources_out) {
  // |device_list| is owned by |resources_dict|
  const base::Value::List* device_list = resources_dict.FindList("devices");
  if (!device_list) {
    // The device list is optional.
    return true;
  }
  size_t num_devices = device_list->size();
  for (size_t i = 0; i < num_devices; ++i) {
    OciLinuxCgroupDevice device;

    if (!(*device_list)[i].is_dict()) {
      LOG(ERROR) << "Fail to get device " << i;
      return false;
    }
    const base::Value::Dict& dev = (*device_list)[i].GetDict();

    std::optional<bool> allow = dev.FindBool("allow");
    if (!allow.has_value()) {
      LOG(ERROR) << "Fail to get allow value for device " << i;
      return false;
    }
    device.allow = *allow;
    const std::string* access = dev.FindString("access");
    // Optional, default to all perms.
    device.access = access ? *access : "rwm";
    const std::string* type = dev.FindString("type");
    // Optional, default to both a means all.
    device.type = type ? *type : "a";
    if (!ParseIntFromDict(dev, "major", &device.major))
      device.major = -1;  // Optional, -1 will map to all devices.
    if (!ParseIntFromDict(dev, "minor", &device.minor))
      device.minor = -1;  // Optional, -1 will map to all devices.

    resources_out->devices.push_back(device);
  }

  return true;
}

// Parses the list of namespaces and fills |namespaces_out| with them.
bool ParseNamespaces(const base::Value::List* namespaces_list,
                     std::vector<OciNamespace>* namespaces_out) {
  for (size_t i = 0; i < namespaces_list->size(); ++i) {
    OciNamespace new_namespace;
    if (!(*namespaces_list)[i].is_dict()) {
      LOG(ERROR) << "Failed to get namespace " << i;
      return false;
    }
    const base::Value::Dict& ns = (*namespaces_list)[i].GetDict();
    const std::string* type = ns.FindString("type");
    if (!type) {
      LOG(ERROR) << "Namespace " << i << " missing type";
      return false;
    }
    new_namespace.type = *type;
    const std::string* path = ns.FindString("path");
    if (path)
      new_namespace.path = base::FilePath(*path);
    namespaces_out->push_back(new_namespace);
  }
  return true;
}

// Parse the list of device nodes that the container needs to run.
bool ParseDeviceList(const base::Value::Dict& linux_dict,
                     OciConfigPtr const& config_out) {
  // |device_list| is owned by |linux_dict|
  const base::Value::List* device_list = linux_dict.FindList("devices");
  if (!device_list) {
    // The device list is optional.
    return true;
  }
  size_t num_devices = device_list->size();
  for (size_t i = 0; i < num_devices; ++i) {
    OciLinuxDevice device;

    if (!(*device_list)[i].is_dict()) {
      LOG(ERROR) << "Fail to get device " << i;
      return false;
    }
    const base::Value::Dict& dev = (*device_list)[i].GetDict();
    const std::string* path = dev.FindString("path");
    if (!path) {
      LOG(ERROR) << "Fail to get path for dev";
      return false;
    }
    device.path = base::FilePath(*path);
    const std::string* type = dev.FindString("type");
    if (!type) {
      LOG(ERROR) << "Fail to get type for " << device.path.value();
      return false;
    }
    device.type = *type;
    std::optional<bool> dynamic_major = dev.FindBool("dynamicMajor");
    if (dynamic_major.has_value())
      device.dynamicMajor = *dynamic_major;
    if (device.dynamicMajor) {
      if (dev.Find("major")) {
        LOG(WARNING)
            << "Ignoring \"major\" since \"dynamicMajor\" is specified for "
            << device.path.value();
      }
    } else {
      if (!ParseIntFromDict(dev, "major", &device.major))
        return false;
    }

    std::optional<bool> dynamic_minor = dev.FindBool("dynamicMinor");
    if (dynamic_minor.has_value())
      device.dynamicMinor = *dynamic_minor;
    if (device.dynamicMinor) {
      if (dev.Find("minor")) {
        LOG(WARNING)
            << "Ignoring \"minor\" since \"dynamicMinor\" is specified for "
            << device.path.value();
      }
    } else {
      if (!ParseIntFromDict(dev, "minor", &device.minor))
        return false;
    }
    if (!ParseIntFromDict(dev, "fileMode", &device.fileMode))
      return false;
    if (!ParseIntFromDict(dev, "uid", &device.uid))
      return false;
    if (!ParseIntFromDict(dev, "gid", &device.gid))
      return false;

    config_out->linux_config.devices.push_back(device);
  }

  return true;
}

// Parses the list of ID mappings and fills |mappings_out| with them.
bool ParseLinuxIdMappings(const base::Value::List* id_map_list,
                          std::vector<OciLinuxNamespaceMapping>* mappings_out) {
  for (size_t i = 0; i < id_map_list->size(); ++i) {
    if (!(*id_map_list)[i].is_dict()) {
      LOG(ERROR) << "Fail to get id map " << i;
      return false;
    }
    const base::Value::Dict& map = (*id_map_list)[i].GetDict();
    OciLinuxNamespaceMapping new_map;
    if (!ParseIntFromDict(map, "hostID", &new_map.hostID))
      return false;
    if (!ParseIntFromDict(map, "containerID", &new_map.containerID))
      return false;
    if (!ParseIntFromDict(map, "size", &new_map.size))
      return false;
    mappings_out->push_back(new_map);
  }
  return true;
}

// Parses seccomp syscall args.
bool ParseSeccompArgs(const base::Value::Dict& syscall_dict,
                      OciSeccompSyscall* syscall_out) {
  const base::Value::List* args = syscall_dict.FindList("args");
  if (args) {
    for (const auto& arg : *args) {
      if (!arg.is_dict()) {
        LOG(ERROR) << "Failed to pars args dict for " << syscall_out->name;
        return false;
      }
      const auto& args_dict = arg.GetDict();
      OciSeccompArg this_arg;
      if (!ParseIntFromDict(args_dict, "index", &this_arg.index))
        return false;
      if (!ParseIntFromDict(args_dict, "value", &this_arg.value))
        return false;
      if (!ParseIntFromDict(args_dict, "value2", &this_arg.value2))
        return false;
      const std::string* op = args_dict.FindString("op");
      if (!op) {
        LOG(ERROR) << "Failed to parse op for arg " << this_arg.index << " of "
                   << syscall_out->name;
        return false;
      }
      this_arg.op = *op;
      syscall_out->args.push_back(this_arg);
    }
  }
  return true;
}

// Parses the seccomp node if it is present.
bool ParseSeccompInfo(const base::Value::Dict& seccomp_dict,
                      OciSeccomp* seccomp_out) {
  const std::string* default_action = seccomp_dict.FindString("defaultAction");
  if (!default_action)
    return false;
  seccomp_out->defaultAction = *default_action;
  // Gets the list of architectures.
  const base::Value::List* architectures =
      seccomp_dict.FindList("architectures");
  if (!architectures) {
    LOG(ERROR) << "Fail to read seccomp architectures";
    return false;
  }
  for (const auto& this_arch : *architectures) {
    if (!this_arch.is_string()) {
      LOG(ERROR) << "Fail to parse seccomp architecture list";
      return false;
    }
    seccomp_out->architectures.push_back(this_arch.GetString());
  }

  // Gets the list of syscalls.
  const base::Value::List* syscalls = seccomp_dict.FindList("syscalls");
  if (!syscalls) {
    LOG(ERROR) << "Fail to read seccomp syscalls";
    return false;
  }
  for (size_t i = 0; i < syscalls->size(); ++i) {
    if (!(*syscalls)[i].is_dict()) {
      LOG(ERROR) << "Fail to parse seccomp syscalls list";
      return false;
    }
    const base::Value::Dict& syscall_dict = (*syscalls)[i].GetDict();
    OciSeccompSyscall this_syscall;
    const std::string* name = syscall_dict.FindString("name");
    if (!name) {
      LOG(ERROR) << "Fail to parse syscall name " << i;
      return false;
    }
    this_syscall.name = *name;
    const std::string* action = syscall_dict.FindString("action");
    if (!action) {
      LOG(ERROR) << "Fail to parse syscall action for " << this_syscall.name;
      return false;
    }
    this_syscall.action = *action;
    if (!ParseSeccompArgs(syscall_dict, &this_syscall))
      return false;
    seccomp_out->syscalls.push_back(this_syscall);
  }

  return true;
}

constexpr std::pair<const char*, int> kMountPropagationMapping[] = {
    {"rprivate", MS_PRIVATE | MS_REC}, {"private", MS_PRIVATE},
    {"rslave", MS_SLAVE | MS_REC},     {"slave", MS_SLAVE},
    {"rshared", MS_SHARED | MS_REC},   {"shared", MS_SHARED},
    {"", MS_SLAVE | MS_REC},  // Default value.
};

bool ParseMountPropagationFlags(const std::string& propagation,
                                int* propagation_flags_out) {
  for (const auto& entry : kMountPropagationMapping) {
    if (propagation == entry.first) {
      *propagation_flags_out = entry.second;
      return true;
    }
  }
  LOG(ERROR) << "Unrecognized mount propagation flags: " << propagation;
  return false;
}

constexpr std::pair<const char*, uint64_t> kSecurebitsMapping[] = {
#define SECUREBIT_MAP_ENTRY(secbit) \
  { #secbit, SECBIT_##secbit }
    SECUREBIT_MAP_ENTRY(NOROOT),
    SECUREBIT_MAP_ENTRY(NOROOT_LOCKED),
    SECUREBIT_MAP_ENTRY(NO_SETUID_FIXUP),
    SECUREBIT_MAP_ENTRY(NO_SETUID_FIXUP_LOCKED),
    SECUREBIT_MAP_ENTRY(KEEP_CAPS),
    SECUREBIT_MAP_ENTRY(KEEP_CAPS_LOCKED),
#if defined(SECBIT_NO_CAP_AMBIENT_RAISE)
    // Kernels < v4.4 do not have this.
    SECUREBIT_MAP_ENTRY(NO_CAP_AMBIENT_RAISE),
    SECUREBIT_MAP_ENTRY(NO_CAP_AMBIENT_RAISE_LOCKED),
#endif  // SECBIT_NO_CAP_AMBIENT_RAISE
#undef SECUREBIT_MAP_ENTRY
};

bool ParseSecurebit(const std::string& securebit_name, uint64_t* mask_out) {
  for (const auto& entry : kSecurebitsMapping) {
    if (securebit_name == entry.first) {
      *mask_out = entry.second;
      return true;
    }
  }
  LOG(ERROR) << "Unrecognized securebit name: " << securebit_name;
  return false;
}

bool ParseSkipSecurebitsMask(const base::Value::List& skip_securebits_list,
                             uint64_t* securebits_mask_out) {
  size_t num_securebits = skip_securebits_list.size();
  for (size_t i = 0; i < num_securebits; ++i) {
    const base::Value& securebit_name = skip_securebits_list[i];
    if (!securebit_name.is_string()) {
      LOG(ERROR) << "Fail to get securebit name " << i;
      return false;
    }
    uint64_t mask = 0;
    if (!ParseSecurebit(securebit_name.GetString(), &mask))
      return false;
    *securebits_mask_out |= mask;
  }
  return true;
}

// Parses the cpu node if it is present.
bool ParseCpuInfo(const base::Value::Dict& cpu_dict, OciCpu* cpu_out) {
  ParseIntFromDict(cpu_dict, "shares", &cpu_out->shares);
  ParseIntFromDict(cpu_dict, "quota", &cpu_out->quota);
  ParseIntFromDict(cpu_dict, "period", &cpu_out->period);
  ParseIntFromDict(cpu_dict, "realtimeRuntime", &cpu_out->realtimeRuntime);
  ParseIntFromDict(cpu_dict, "realtimePeriod", &cpu_out->realtimePeriod);
  return true;
}

// Parses the linux node which has information about setting up a user
// namespace, and the list of devices for the container.
bool ParseLinuxConfigDict(const base::Value::Dict& runtime_root_dict,
                          OciConfigPtr const& config_out) {
  // |linux_dict| is owned by |runtime_root_dict|
  const base::Value::Dict* linux_dict = runtime_root_dict.FindDict("linux");
  if (!linux_dict) {
    LOG(ERROR) << "Fail to get linux dictionary from the runtime dictionary";
    return false;
  }

  // |uid_map_list| is owned by |linux_dict|
  const base::Value::List* uid_map_list = linux_dict->FindList("uidMappings");
  if (uid_map_list)
    ParseLinuxIdMappings(uid_map_list, &config_out->linux_config.uidMappings);

  // |gid_map_list| is owned by |linux_dict|
  const base::Value::List* gid_map_list = linux_dict->FindList("gidMappings");
  if (gid_map_list)
    ParseLinuxIdMappings(gid_map_list, &config_out->linux_config.gidMappings);

  if (!ParseDeviceList(*linux_dict, config_out))
    return false;

  const base::Value::Dict* resources_dict = linux_dict->FindDict("resources");
  if (resources_dict) {
    if (!ParseResources(*resources_dict, &config_out->linux_config.resources))
      return false;
  }

  const base::Value::List* namespaces_list = linux_dict->FindList("namespaces");
  if (namespaces_list) {
    if (!ParseNamespaces(namespaces_list, &config_out->linux_config.namespaces))
      return false;
  }

  const base::Value::Dict* seccomp_dict = linux_dict->FindDict("seccomp");
  if (seccomp_dict) {
    if (!ParseSeccompInfo(*seccomp_dict, &config_out->linux_config.seccomp))
      return false;
  }

  const std::string* rootfs_propagation_string =
      linux_dict->FindString("rootfsPropagation");
  if (!ParseMountPropagationFlags(
          rootfs_propagation_string ? *rootfs_propagation_string
                                    : base::EmptyString(),  // Optional
          &config_out->linux_config.rootfsPropagation)) {
    return false;
  }

  const std::string* cgroups_path_string =
      linux_dict->FindString("cgroupsPath");
  if (cgroups_path_string)
    config_out->linux_config.cgroupsPath = base::FilePath(*cgroups_path_string);

  const std::string* alt_syscall = linux_dict->FindString("altSyscall");
  config_out->linux_config.altSyscall =
      alt_syscall ? *alt_syscall : base::EmptyString();  // Optional

  std::optional<bool> core_sched = linux_dict->FindBool("coreSched");
  config_out->linux_config.coreSched = core_sched.value_or(false);  // Optional

  const base::Value::List* skip_securebits_list =
      linux_dict->FindList("skipSecurebits");
  if (skip_securebits_list) {
    if (!ParseSkipSecurebitsMask(*skip_securebits_list,
                                 &config_out->linux_config.skipSecurebits)) {
      return false;
    }
  } else {
    config_out->linux_config.skipSecurebits = 0;  // Optional
  }

  const base::Value::Dict* cpu_dict = linux_dict->FindDict("cpu");
  if (cpu_dict) {
    if (!ParseCpuInfo(*cpu_dict, &config_out->linux_config.cpu))
      return false;
  }

  return true;
}

bool HostnameValid(const std::string& hostname) {
  if (hostname.length() > 255)
    return false;

  const std::regex name("^[0-9a-zA-Z]([0-9a-zA-Z-]*[0-9a-zA-Z])?$");
  if (!std::regex_match(hostname, name))
    return false;

  const std::regex double_dash("--");
  if (std::regex_match(hostname, double_dash))
    return false;

  return true;
}

bool ParseHooksList(const base::Value::List& hooks_list,
                    std::vector<OciHook>* hooks_out,
                    const std::string& hook_type) {
  size_t num_hooks = hooks_list.size();
  for (size_t i = 0; i < num_hooks; ++i) {
    OciHook hook;
    if (!hooks_list[i].is_dict()) {
      LOG(ERROR) << "Fail to get " << hook_type << " hook item " << i;
      return false;
    }
    const base::Value::Dict& hook_dict = hooks_list[i].GetDict();

    const std::string* path = hook_dict.FindString("path");
    if (!path) {
      LOG(ERROR) << "Fail to get path of " << hook_type << " hook " << i;
      return false;
    }
    hook.path = base::FilePath(*path);

    const base::Value::List* hook_args = hook_dict.FindList("args");
    // args are optional.
    if (hook_args) {
      size_t num_args = hook_args->size();
      for (size_t j = 0; j < num_args; ++j) {
        const base::Value& arg = (*hook_args)[j];
        if (!arg.is_string()) {
          LOG(ERROR) << "Fail to get arg " << j << " of " << hook_type
                     << " hook " << i;
          return false;
        }
        hook.args.push_back(arg.GetString());
      }
    }

    const base::Value::List* hook_envs = hook_dict.FindList("env");
    // envs are optional.
    if (hook_envs) {
      size_t num_env = hook_envs->size();
      for (size_t j = 0; j < num_env; ++j) {
        const base::Value& env = (*hook_envs)[j];
        if (!env.is_string()) {
          LOG(ERROR) << "Fail to get env " << j << " of " << hook_type
                     << " hook " << i;
          return false;
        }
        std::vector<std::string> kvp = base::SplitString(
            env.GetString(), "=", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
        if (kvp.size() != 2) {
          LOG(ERROR) << "Fail to parse env \"" << env.GetString()
                     << "\". Must be in name=value format.";
          return false;
        }
        hook.env.insert(std::make_pair(kvp[0], kvp[1]));
      }
    }

    std::optional<int> timeout_seconds = hook_dict.FindInt("timeout");
    // timeout is optional.
    hook.timeout = timeout_seconds.has_value() ? base::Seconds(*timeout_seconds)
                                               : base::TimeDelta::Max();

    hooks_out->emplace_back(std::move(hook));
  }
  return true;
}

bool ParseHooks(const base::Value::Dict& config_root_dict,
                OciConfigPtr const& config_out) {
  const base::Value::Dict* hooks_config_dict =
      config_root_dict.FindDict("hooks");
  if (!hooks_config_dict) {
    // Hooks are optional.
    return true;
  }

  const base::Value::List* hooks_list =
      hooks_config_dict->FindList("precreate");
  if (hooks_list) {
    if (!ParseHooksList(*hooks_list, &config_out->pre_create_hooks,
                        "precreate")) {
      return false;
    }
  }
  hooks_list = hooks_config_dict->FindList("prechroot");
  if (hooks_list) {
    if (!ParseHooksList(*hooks_list, &config_out->pre_chroot_hooks,
                        "prechroot")) {
      return false;
    }
  }
  hooks_list = hooks_config_dict->FindList("prestart");
  if (hooks_list) {
    if (!ParseHooksList(*hooks_list, &config_out->pre_start_hooks, "prestart"))
      return false;
  }
  hooks_list = hooks_config_dict->FindList("poststart");
  if (hooks_list) {
    if (!ParseHooksList(*hooks_list, &config_out->post_start_hooks,
                        "poststart"))
      return false;
  }
  hooks_list = hooks_config_dict->FindList("poststop");
  if (hooks_list) {
    if (!ParseHooksList(*hooks_list, &config_out->post_stop_hooks, "poststop"))
      return false;
  }
  return true;
}

// Parses the configuration file for the container.  The config file specifies
// basic filesystem info and details about the process to be run.  namespace,
// cgroup, and syscall configurations are also specified
bool ParseConfigDict(const base::Value::Dict& config_root_dict,
                     OciConfigPtr const& config_out) {
  const std::string* oci_version = config_root_dict.FindString("ociVersion");
  if (!oci_version) {
    LOG(ERROR) << "Failed to parse ociVersion";
    return false;
  }
  config_out->ociVersion = *oci_version;
  const std::string* host_name = config_root_dict.FindString("hostname");
  if (!host_name) {
    LOG(ERROR) << "Failed to parse hostname";
    return false;
  }
  config_out->hostname = *host_name;
  if (!HostnameValid(config_out->hostname)) {
    LOG(ERROR) << "Invalid hostname " << config_out->hostname;
    return false;
  }

  // Platform info
  if (!ParsePlatformConfig(config_root_dict, config_out)) {
    return false;
  }

  // Root fs info
  if (!ParseRootFileSystemConfig(config_root_dict, config_out)) {
    return false;
  }

  // Process info
  if (!ParseProcessConfig(config_root_dict, config_out)) {
    return false;
  }

  // Get a list of mount points and mounts.
  if (!ParseMounts(config_root_dict, config_out)) {
    LOG(ERROR) << "Failed to parse mounts";
    return false;
  }

  // Hooks info
  if (!ParseHooks(config_root_dict, config_out)) {
    return false;
  }

  // Parse linux node.
  if (!ParseLinuxConfigDict(config_root_dict, config_out)) {
    LOG(ERROR) << "Failed to parse the linux node";
    return false;
  }

  return true;
}

}  // anonymous namespace

bool ParseContainerConfig(const std::string& config_json_data,
                          OciConfigPtr const& config_out) {
  auto result = base::JSONReader::ReadAndReturnValueWithError(
      config_json_data, base::JSON_PARSE_RFC);
  if (!result.has_value()) {
    LOG(ERROR) << "Fail to parse config.json: " << result.error().message;
    return false;
  }
  if (!result->is_dict()) {
    LOG(ERROR) << "Fail to parse root dictionary from config.json";
    return false;
  }
  if (!ParseConfigDict(result->GetDict(), config_out)) {
    return false;
  }

  return true;
}

}  // namespace run_oci
