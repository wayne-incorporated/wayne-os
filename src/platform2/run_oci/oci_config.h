// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Container configuration from the config.json data as specified in
// https://github.com/opencontainers/runtime-spec/tree/v1.0.0-rc2

#ifndef RUN_OCI_OCI_CONFIG_H_
#define RUN_OCI_OCI_CONFIG_H_

#include <linux/capability.h>
#include <stdint.h>
#include <sys/resource.h>

#include <bitset>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/time/time.h>

namespace run_oci {

struct OciPlatform {
  std::string os;
  std::string arch;
};

struct OciProcessUser {
  uint32_t uid;
  uint32_t gid;
  std::vector<uint32_t> additionalGids;  // Optional
};

using CapSet = std::bitset<CAP_LAST_CAP + 1>;

struct OciProcessRlimit {
  int type;
  rlim_t hard;
  rlim_t soft;
};

using OciEnvironment = std::map<std::string, std::string>;

struct OciProcess {
  bool terminal = false;  // Optional
  OciProcessUser user;
  std::vector<std::string> args;
  OciEnvironment env;  // Optional
  base::FilePath cwd;
  std::map<std::string, CapSet> capabilities;  // Optional
  std::vector<OciProcessRlimit> rlimits;       // Optional
  std::string selinuxLabel;
  mode_t umask = 0022;  // Optional, Chrome OS extension
  // Unused: apparmorProfile, noNewPrivileges
};

struct OciRoot {
  base::FilePath path;
  bool readonly = false;  // Optional
};

struct OciMount {
  base::FilePath destination;
  std::string type;
  base::FilePath source;
  std::vector<std::string> options;  // Optional
  bool performInIntermediateNamespace =
      false;  // Optional, Chrome OS extension.
};

struct OciLinuxNamespaceMapping {
  uint32_t hostID;
  uint32_t containerID;
  uint32_t size;
};

struct OciLinuxDevice {
  std::string type;
  base::FilePath path;
  uint32_t major = 0;         // Optional
  uint32_t minor = 0;         // Optional
  uint32_t fileMode = 0000;   // Optional
  uint32_t uid = 0;           // Optional
  uint32_t gid = 0;           // Optional
  bool dynamicMajor = false;  // Optional, Chrome OS extension.
  bool dynamicMinor = false;  // Optional, Chrome OS extension.
};

struct OciSeccompArg {
  uint32_t index;
  uint64_t value;
  uint64_t value2;
  std::string op;
};

struct OciSeccompSyscall {
  std::string name;
  std::string action;
  std::vector<OciSeccompArg> args;  // Optional
};

struct OciLinuxCgroupDevice {
  bool allow;
  std::string access;   // Optional
  std::string type;     // Optional
  uint32_t major = -1;  // Optional
  uint32_t minor = -1;  // Optional
};

struct OciLinuxResources {
  std::vector<OciLinuxCgroupDevice> devices;
  // Other fields remain unused.
};

struct OciSeccomp {
  std::string defaultAction;
  std::vector<std::string> architectures;
  std::vector<OciSeccompSyscall> syscalls;
};

struct OciNamespace {
  std::string type;
  base::FilePath path;  // Optional
};

struct OciCpu {
  uint64_t shares;          // Optional
  int64_t quota;            // Optional
  uint64_t period;          // Optional
  int64_t realtimeRuntime;  // Optional
  uint64_t realtimePeriod;  // Optional
  // Unused: cpus, mems
};

struct OciLinux {
  std::vector<OciLinuxDevice> devices;  // Optional
  base::FilePath cgroupsPath;           // Optional
  std::vector<OciNamespace> namespaces;
  OciLinuxResources resources;                        // Optional
  std::vector<OciLinuxNamespaceMapping> uidMappings;  // Optional
  std::vector<OciLinuxNamespaceMapping> gidMappings;  // Optional
  OciSeccomp seccomp;                                 // Optional
  int rootfsPropagation = 0;                          // Optional
  OciCpu cpu;                                         // Optional
  std::string altSyscall;       // Optional, Chrome OS extension.
  uint64_t skipSecurebits = 0;  // Optional, Chrome OS extension.
  bool coreSched = 0;           // Optional, Chrome OS extension.
  // Unused: maskedPaths, readonlyPaths, mountLabel, sysctl
};

struct OciHook {
  base::FilePath path;
  std::vector<std::string> args;  // Optional
  OciEnvironment env;             // Optional
  base::TimeDelta timeout;        // Optional
};

struct OciConfig {
  std::string ociVersion;
  OciPlatform platform;
  OciRoot root;
  OciProcess process;
  std::string hostname;                   // Optional
  std::vector<OciMount> mounts;           // Optional
  std::vector<OciHook> pre_create_hooks;  // Optional, Chrome OS extension.
  std::vector<OciHook> pre_chroot_hooks;  // Optional, Chrome OS extension.
  std::vector<OciHook> pre_start_hooks;   // Optional
  std::vector<OciHook> post_start_hooks;  // Optional
  std::vector<OciHook> post_stop_hooks;   // Optional
  // json field name - linux
  OciLinux linux_config;  // Optional
  // Unused: annotations
};

}  // namespace run_oci

#endif  // RUN_OCI_OCI_CONFIG_H_
