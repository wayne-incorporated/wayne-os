// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "run_oci/container_config_parser.h"

#include <linux/securebits.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/mount.h>
#include <sys/resource.h>

#include <map>
#include <vector>

#include <base/values.h>
#include <gtest/gtest.h>

#include "run_oci/oci_config.h"

namespace {

const char kBasicJsonData[] = R"json(
    {
        "ociVersion": "1.0.0-rc1",
        "platform": {
            "os": "linux",
            "arch": "amd64"
        },
        "root": {
            "path": "rootfs",
            "readonly": true
        },
        "process": {
            "terminal": true,
            "user": {
                "uid": 0,
                "gid": 0,
                "additionalGids": [1, 2]
            },
            "args": [
                "sh"
            ],
            "env": [
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "TERM=xterm"
            ],
            "cwd": "/",
            "capabilities": {
                "effective": [
                    "CAP_AUDIT_WRITE",
                    "CAP_KILL",
                    "CAP_NET_BIND_SERVICE"
                ],
                "bounding": [
                    "CAP_AUDIT_WRITE",
                    "CAP_KILL",
                    "CAP_NET_BIND_SERVICE"
                ],
                "inheritable": [
                    "CAP_AUDIT_WRITE",
                    "CAP_KILL",
                    "CAP_NET_BIND_SERVICE"
                ],
                "permitted": [
                    "CAP_AUDIT_WRITE",
                    "CAP_KILL",
                    "CAP_NET_BIND_SERVICE"
                ],
                "ambient": [
                    "CAP_AUDIT_WRITE",
                    "CAP_KILL",
                    "CAP_NET_BIND_SERVICE"
                ]
            },
            "rlimits": [
                {
                    "type": "RLIMIT_NICE",
                    "hard": 12,
                    "soft": 11
                }
            ],
            "noNewPrivileges": true,
            "umask": 0
        },
        "hostname": "tester",
        "mounts": [
            {
                "destination": "/proc",
                "type": "proc",
                "source": "proc"
            },
            {
                "destination": "/dev",
                "type": "tmpfs",
                "source": "tmpfs",
                "options": [
                        "nosuid",
                        "strictatime",
                        "mode=755",
                        "size=65536k"
                ]
            },
            {
                "destination": "/dev/pts",
                "type": "devpts",
                "source": "devpts",
                "options": [
                        "nosuid",
                        "noexec",
                        "newinstance",
                        "ptmxmode=0666",
                        "mode=0620",
                        "gid=5"
                ]
            },
            {
                "destination": "/dev/shm",
                "type": "tmpfs",
                "source": "shm",
                "options": [
                        "nosuid",
                        "noexec",
                        "nodev",
                        "mode=1777",
                        "size=65536k"
                ]
            },
            {
                "destination": "/dev/mqueue",
                "type": "mqueue",
                "source": "mqueue",
                "options": [
                        "nosuid",
                        "noexec",
                        "nodev"
                ]
            },
            {
                "destination": "/sys",
                "type": "sysfs",
                "source": "sysfs",
                "options": [
                        "nosuid",
                        "noexec",
                        "nodev",
                        "ro"
                ]
            },
            {
                "destination": "/sys/fs/cgroup",
                "type": "cgroup",
                "source": "cgroup",
                "options": [
                        "nosuid",
                        "noexec",
                        "nodev",
                        "relatime",
                        "ro"
                ]
            }
        ],
        "hooks" : {
            "precreate": [
                {
                    "path": "/usr/bin/setup-mounts"
                }
            ],
            "prestart": [
                {
                    "path": "/usr/bin/fix-mounts",
                    "args": ["fix-mounts", "arg1", "arg2"],
                    "env":  [ "key1=value1"]
                },
                {
                    "path": "/usr/bin/setup-network"
                }
            ],
            "poststart": [
                {
                    "path": "/usr/bin/notify-start",
                    "timeout": 5
                }
            ],
            "poststop": [
                {
                    "path": "/usr/sbin/cleanup.sh",
                    "args": ["cleanup.sh", "-f"]
                }
            ]
        },
        "linux": {
            "rootfsPropagation": "rprivate",
            "altSyscall": "android",
            "cgroupsPath": "/session_manager_containers",
            "skipSecurebits": [
                "KEEP_CAPS",
                "KEEP_CAPS_LOCKED"
            ],
            "devices": [
                {
                    "path": "/dev/fuse",
                    "type": "c",
                    "major": 10,
                    "minor": 229,
                    "fileMode": 438,
                    "uid": 0,
                    "gid": 3221225472
                },
                {
                    "path": "/dev/sda",
                    "type": "b",
                    "major": 8,
                    "minor": 0,
                    "fileMode": 432,
                    "uid": 0,
                    "gid": 0
                },
                {
                    "path": "/dev/binder",
                    "type": "c",
                    "major": 10,
                    "dynamicMinor": true,
                    "fileMode": 438,
                    "uid": 0,
                    "gid": 0
                }
            ],
            "resources": {
                "devices": [
                    {
                        "allow": false,
                        "access": "rwm"
                    }
                ],
                "network": {
                    "classID": 1048577,
                    "priorities": [
                        {
                            "name": "eth0",
                            "priority": 500
                        },
                        {
                            "name": "eth1",
                            "priority": 1000
                        }
                    ]
                }
            },
            "namespaces": [
                {
                    "type": "pid",
                    "path": "/proc/1234/ns/pid"
                },
                {
                    "type": "network"
                },
                {
                    "type": "ipc"
                },
                {
                    "type": "uts"
                },
                {
                    "type": "mount"
                }
            ],
            "uidMappings": [
                {
                    "hostID": 1000,
                    "containerID": 0,
                    "size": 10
                }
            ],
            "gidMappings": [
                {
                    "hostID": 1000,
                    "containerID": 0,
                    "size": 10
                }
            ],
            "maskedPaths": [
                "/proc/kcore",
                "/proc/latency_stats",
                "/proc/timer_list",
                "/proc/timer_stats",
                "/proc/sched_debug"
            ],
            "readonlyPaths": [
                "/proc/asound",
                "/proc/bus",
                "/proc/fs",
                "/proc/irq",
                "/proc/sys",
                "/proc/sysrq-trigger"
            ],
            "seccomp": {
                "defaultAction": "SCP_ACT_KILL",
                "architectures": [
                    "SCP_ARCH_X86"
                ],
                "syscalls": [
                    {
                        "name": "read",
                        "action": "SCP_ACT_ALLOW"
                    },
                    {
                        "name": "write",
                        "action": "SCP_ACT_ALLOW",
                        "args": [
                            {
                                "index": 1,
                                "value": 255,
                                "value2": 4,
                                "op": "SCMP_CMP_EQ"
                            }
                        ]
                    }
                ]
            },
            "cpu": {
                "shares": 1024,
                "quota": 1000000,
                "period": 500000,
                "realtimeRuntime": 950000,
                "realtimePeriod": 1000000
            }
        }
    }
)json";

const char kStrippedJsonData[] = R"json(
    {
        "ociVersion": "1.0.0-rc1",
        "platform": {
            "os": "linux",
            "arch": "amd64"
        },
        "root": {
            "path": "rootfs",
            "readonly": true
        },
        "process": {
            "terminal": true,
            "user": {
                "uid": 0,
                "gid": 0
            },
            "args": [
                "sh"
            ],
            "cwd": "/",
            "noNewPrivileges": true
        },
        "hostname": "tester",
        "mounts": [
            {
                "destination": "/proc",
                "type": "proc",
                "source": "proc"
            }
        ],
        "linux": {
            "uidMappings": [
                {
                    "hostID": 1000,
                    "containerID": 0,
                    "size": 10
                }
            ],
            "gidMappings": [
                {
                    "hostID": 1000,
                    "containerID": 0,
                    "size": 10
                }
            ]
        }
    }
)json";

const char kInvalidHostnameJsonData[] = R"json(
    {
        "ociVersion": "1.0.0-rc1",
        "platform": {
            "os": "linux",
            "arch": "amd64"
        },
        "root": {
            "path": "rootfs",
            "readonly": true
        },
        "process": {
            "terminal": true,
            "user": {
                "uid": 0,
                "gid": 0
            },
            "args": [
                "sh"
            ],
            "cwd": "/",
            "noNewPrivileges": true
        },
        "hostname": "../secrets",
        "mounts": [
            {
                "destination": "/proc",
                "type": "proc",
                "source": "proc"
            }
        ],
        "linux": {
            "uidMappings": [
                {
                    "hostID": 1000,
                    "containerID": 0,
                    "size": 10
                }
            ],
            "gidMappings": [
                {
                    "hostID": 1000,
                    "containerID": 0,
                    "size": 10
                }
            ]
        }
    }
)json";

}  // anonymous namespace

namespace run_oci {

TEST(OciConfigParserTest, TestBasicConfig) {
  OciConfigPtr basic_config(new OciConfig());
  ASSERT_TRUE(ParseContainerConfig(kBasicJsonData, basic_config));

  EXPECT_EQ(basic_config->ociVersion, "1.0.0-rc1");
  EXPECT_EQ(basic_config->platform.os, "linux");
  EXPECT_EQ(basic_config->root.path, base::FilePath("rootfs"));
  EXPECT_EQ(basic_config->root.readonly, true);
  EXPECT_EQ(basic_config->process.terminal, true);
  EXPECT_EQ(basic_config->process.user.uid, 0);
  EXPECT_EQ(basic_config->process.user.gid, 0);
  EXPECT_EQ(basic_config->process.user.additionalGids,
            std::vector<uint32_t>({1, 2}));
  EXPECT_EQ(basic_config->process.args.size(), 1);
  EXPECT_EQ(basic_config->process.args[0], "sh");
  EXPECT_EQ(basic_config->process.env.size(), 2);
  EXPECT_EQ(
      basic_config->process.env,
      (OciEnvironment{
          {"PATH",
           "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
          {"TERM", "xterm"}}));
  EXPECT_EQ(basic_config->process.cwd, base::FilePath("/"));
  EXPECT_EQ(basic_config->process.rlimits.size(), 1);
  EXPECT_EQ(basic_config->process.rlimits[0].type, RLIMIT_NICE);
  EXPECT_EQ(basic_config->process.rlimits[0].soft, 11);
  EXPECT_EQ(basic_config->process.rlimits[0].hard, 12);
  EXPECT_EQ(basic_config->process.umask, 0);
  EXPECT_EQ(basic_config->hostname, "tester");
  ASSERT_EQ(basic_config->mounts.size(), 7);
  EXPECT_EQ(basic_config->mounts[0].options.size(), 0);
  EXPECT_EQ(basic_config->mounts[1].destination, base::FilePath("/dev"));
  EXPECT_EQ(basic_config->mounts[2].options.size(), 6);
  EXPECT_EQ(MS_PRIVATE | MS_REC, basic_config->linux_config.rootfsPropagation);
  EXPECT_EQ("android", basic_config->linux_config.altSyscall);
  EXPECT_EQ(base::FilePath("/session_manager_containers"),
            basic_config->linux_config.cgroupsPath);
  EXPECT_EQ(SECBIT_KEEP_CAPS | SECBIT_KEEP_CAPS_LOCKED,
            basic_config->linux_config.skipSecurebits);
  // Devices
  ASSERT_EQ(3, basic_config->linux_config.devices.size());
  OciLinuxDevice* dev = &basic_config->linux_config.devices[0];
  EXPECT_EQ(dev->type, "c");
  EXPECT_EQ(dev->path, base::FilePath("/dev/fuse"));
  EXPECT_EQ(dev->fileMode, 438);
  EXPECT_EQ(dev->uid, 0);
  EXPECT_EQ(dev->gid, 3221225472);  // INT32_MAX < id < UINT32_MAX
  dev = &basic_config->linux_config.devices[2];
  EXPECT_EQ(dev->type, "c");
  EXPECT_EQ(dev->path, base::FilePath("/dev/binder"));
  EXPECT_EQ(dev->fileMode, 438);
  EXPECT_EQ(dev->major, 10);
  EXPECT_EQ(dev->minor, 0);
  EXPECT_EQ(dev->dynamicMinor, true);
  // Namespaces
  ASSERT_EQ(5, basic_config->linux_config.namespaces.size());
  EXPECT_EQ(basic_config->linux_config.namespaces[0].type, "pid");
  EXPECT_EQ(basic_config->linux_config.namespaces[0].path,
            base::FilePath("/proc/1234/ns/pid"));
  EXPECT_EQ(basic_config->linux_config.namespaces[1].type, "network");
  EXPECT_EQ(basic_config->linux_config.namespaces[1].path, base::FilePath(""));
  // Namespace Maps
  ASSERT_EQ(1, basic_config->linux_config.uidMappings.size());
  OciLinuxNamespaceMapping* id_map = &basic_config->linux_config.uidMappings[0];
  EXPECT_EQ(id_map->hostID, 1000);
  EXPECT_EQ(id_map->containerID, 0);
  EXPECT_EQ(id_map->size, 10);
  // seccomp
  OciSeccomp* seccomp = &basic_config->linux_config.seccomp;
  EXPECT_EQ(seccomp->defaultAction, "SCP_ACT_KILL");
  EXPECT_EQ(seccomp->architectures[0], "SCP_ARCH_X86");
  EXPECT_EQ(seccomp->syscalls[0].name, "read");
  EXPECT_EQ(seccomp->syscalls[0].action, "SCP_ACT_ALLOW");
  EXPECT_EQ(seccomp->syscalls[1].name, "write");
  EXPECT_EQ(seccomp->syscalls[1].action, "SCP_ACT_ALLOW");
  EXPECT_EQ(seccomp->syscalls[1].args[0].index, 1);
  EXPECT_EQ(seccomp->syscalls[1].args[0].value, 255);
  EXPECT_EQ(seccomp->syscalls[1].args[0].value2, 4);
  EXPECT_EQ(seccomp->syscalls[1].args[0].op, "SCMP_CMP_EQ");
  // cpu
  OciCpu* cpu = &basic_config->linux_config.cpu;
  EXPECT_EQ(cpu->shares, 1024);
  EXPECT_EQ(cpu->quota, 1000000);
  EXPECT_EQ(cpu->period, 500000);
  EXPECT_EQ(cpu->realtimeRuntime, 950000);
  EXPECT_EQ(cpu->realtimePeriod, 1000000);
  // capabilities
  const auto effective_capset =
      basic_config->process.capabilities.find("effective");
  EXPECT_NE(effective_capset, basic_config->process.capabilities.end());
  EXPECT_EQ(effective_capset->second.to_ullong(),
            (1ull << CAP_AUDIT_WRITE) | (1ull << CAP_KILL) |
                (1ull << CAP_NET_BIND_SERVICE));
  // hooks
  std::vector<OciHook>* pre_create_hooks = &basic_config->pre_create_hooks;
  ASSERT_EQ(pre_create_hooks->size(), 1);
  EXPECT_EQ((*pre_create_hooks)[0].path,
            base::FilePath("/usr/bin/setup-mounts"));
  std::vector<OciHook>* pre_start_hooks = &basic_config->pre_start_hooks;
  EXPECT_EQ(pre_start_hooks->size(), 2);
  EXPECT_EQ((*pre_start_hooks)[0].path, base::FilePath("/usr/bin/fix-mounts"));
  EXPECT_EQ((*pre_start_hooks)[0].args,
            (std::vector<std::string>{"fix-mounts", "arg1", "arg2"}));
  EXPECT_EQ((*pre_start_hooks)[0].env, (OciEnvironment{{"key1", "value1"}}));
  EXPECT_EQ((*pre_start_hooks)[1].path,
            base::FilePath("/usr/bin/setup-network"));
  std::vector<OciHook>* post_start_hooks = &basic_config->post_start_hooks;
  EXPECT_EQ(post_start_hooks->size(), 1);
  EXPECT_EQ((*post_start_hooks)[0].path,
            base::FilePath("/usr/bin/notify-start"));
  EXPECT_EQ((*post_start_hooks)[0].timeout, base::Seconds(5));
}

TEST(OciConfigParserTest, TestStrippedConfig) {
  OciConfigPtr stripped_config(new OciConfig());
  ASSERT_TRUE(ParseContainerConfig(kStrippedJsonData, stripped_config));
}

TEST(OciConfigParserTest, TestInvalidHostnameConfig) {
  OciConfigPtr invalid_config(new OciConfig());
  ASSERT_FALSE(ParseContainerConfig(kInvalidHostnameJsonData, invalid_config));
}

}  // namespace run_oci
