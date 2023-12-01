// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#include <iterator>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_split.h>
#include <gtest/gtest.h>

#include "libcontainer/cgroup.h"
#include "libcontainer/config.h"
#include "libcontainer/container.h"
#include "libcontainer/libcontainer.h"
#include "libcontainer/libcontainer_util.h"

namespace libcontainer {

namespace {

using MinijailHookCallback = base::RepeatingCallback<int()>;

constexpr int kTestCpuShares = 200;
constexpr int kTestCpuQuota = 20000;
constexpr int kTestCpuPeriod = 50000;

struct MockPosixState {
  struct MountArgs {
    std::string source;
    base::FilePath target;
    std::string filesystemtype;
    unsigned long mountflags;
    const void* data;
    bool outside_mount;
  };
  std::vector<MountArgs> mount_args;

  dev_t stat_rdev_ret = makedev(2, 3);

  std::vector<int> kill_sigs;
  base::FilePath mkdtemp_root;
};
MockPosixState* g_mock_posix_state = nullptr;

struct MockCgroupState {
  struct AddedDevice {
    bool allow;
    int major;
    int minor;
    bool read;
    bool write;
    bool modify;
    char type;
  };

  bool freeze_ret = true;
  bool thaw_ret = true;
  bool deny_all_devs_ret = true;
  bool add_device_ret = true;
  bool set_cpu_ret = true;

  int deny_all_devs_called_count;

  std::vector<AddedDevice> added_devices;

  int set_cpu_shares_count;
  int set_cpu_quota_count;
  int set_cpu_period_count;
  int set_cpu_rt_runtime_count;
  int set_cpu_rt_period_count;
};
MockCgroupState* g_mock_cgroup_state = nullptr;

class MockCgroup : public libcontainer::Cgroup {
 public:
  explicit MockCgroup(MockCgroupState* state) : state_(state) {}
  MockCgroup(const MockCgroup&) = delete;
  MockCgroup& operator=(const MockCgroup&) = delete;

  ~MockCgroup() = default;

  static std::unique_ptr<libcontainer::Cgroup> Create(
      base::StringPiece name,
      const base::FilePath& cgroup_root,
      const base::FilePath& cgroup_parent,
      uid_t cgroup_owner,
      gid_t cgroup_group) {
    return std::make_unique<MockCgroup>(g_mock_cgroup_state);
  }

  bool Freeze() override { return state_->freeze_ret; }

  bool Thaw() override { return state_->thaw_ret; }

  bool DenyAllDevices() override {
    ++state_->deny_all_devs_called_count;
    return state_->deny_all_devs_ret;
  }

  bool AddDevice(bool allow,
                 int major,
                 int minor,
                 bool read,
                 bool write,
                 bool modify,
                 char type) override {
    state_->added_devices.emplace_back(MockCgroupState::AddedDevice{
        allow, major, minor, read, write, modify, type});
    return state_->add_device_ret;
  }

  bool SetCpuShares(int shares) override {
    state_->set_cpu_shares_count++;
    return state_->set_cpu_ret;
  }

  bool SetCpuQuota(int quota) override {
    state_->set_cpu_quota_count++;
    return state_->set_cpu_ret;
  }

  bool SetCpuPeriod(int period) override {
    state_->set_cpu_period_count++;
    return state_->set_cpu_ret;
  }

  bool SetCpuRtRuntime(int rt_runtime) override {
    state_->set_cpu_rt_runtime_count++;
    return state_->set_cpu_ret;
  }

  bool SetCpuRtPeriod(int rt_period) override {
    state_->set_cpu_rt_period_count++;
    return state_->set_cpu_ret;
  }

 private:
  MockCgroupState* const state_;
};

struct MockMinijailState {
  std::string alt_syscall_table;
  int ipc_called_count;
  int vfs_called_count;
  int net_called_count;
  int pids_called_count;
  int run_as_init_called_count;
  int user_called_count;
  int cgroups_called_count;
  int wait_called_count;
  int reset_signal_mask_called_count;
  int reset_signal_handlers_called_count;
  int set_supplementary_gids_called_count;
  int pid;
  std::map<minijail_hook_event_t, std::vector<MinijailHookCallback>> hooks;
};
MockMinijailState* g_mock_minijail_state = nullptr;

}  // namespace

TEST(LibcontainerTest, PremountedRunfs) {
  char premounted_runfs[] = "/tmp/cgtest_run/root";
  struct container_config* config = container_config_create();
  ASSERT_NE(nullptr, config);

  container_config_premounted_runfs(config, premounted_runfs);
  const char* result = container_config_get_premounted_runfs(config);
  ASSERT_EQ(0, strcmp(result, premounted_runfs));

  container_config_destroy(config);
}

TEST(LibcontainerTest, PidFilePath) {
  char pid_file_path[] = "/tmp/cgtest_run/root/container.pid";
  struct container_config* config = container_config_create();
  ASSERT_NE(nullptr, config);

  container_config_pid_file(config, pid_file_path);
  const char* result = container_config_get_pid_file(config);
  ASSERT_EQ(0, strcmp(result, pid_file_path));

  container_config_destroy(config);
}

TEST(LibcontainerTest, DumpConfig) {
  struct container_config* config = container_config_create();
  ASSERT_NE(nullptr, config);

  // Confirm that container_config_dump() returns a non-empty string.
  std::unique_ptr<char, decltype(&free)> config_str(
      container_config_dump(config, false /* sort_vector */), free);
  ASSERT_NE(nullptr, config_str.get());
  EXPECT_NE(0U, strlen(config_str.get()));

  // Also confirm that the string has multiple lines.
  EXPECT_LT(1U, base::SplitString(config_str.get(), "\n", base::KEEP_WHITESPACE,
                                  base::SPLIT_WANT_NONEMPTY)
                    .size());

  container_config_destroy(config);
}

class ContainerTest : public ::testing::Test {
 public:
  ContainerTest() = default;
  ContainerTest(const ContainerTest&) = delete;
  ContainerTest& operator=(const ContainerTest&) = delete;

  ~ContainerTest() override = default;

  void SetUp() override {
    g_mock_posix_state = new MockPosixState();
    g_mock_cgroup_state = new MockCgroupState();
    g_mock_minijail_state = new MockMinijailState();
    libcontainer::Cgroup::SetCgroupFactoryForTesting(&MockCgroup::Create);

    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());

    ASSERT_TRUE(base::CreateTemporaryDirInDir(temp_dir_.GetPath(),
                                              "container_test", &rootfs_));

    mount_flags_ = MS_NOSUID | MS_NODEV | MS_NOEXEC;

    config_.reset(new Config());
    container_config_uid_map(config_->get(), "0 0 4294967295");
    container_config_gid_map(config_->get(), "0 0 4294967295");
    container_config_rootfs(config_->get(), rootfs_.value().c_str());

    static const char* kArgv[] = {
        "/sbin/init",
    };
    container_config_program_argv(config_->get(), kArgv, 1);
    container_config_alt_syscall_table(config_->get(), "testsyscalltable");
    container_config_add_mount(config_->get(), "testtmpfs", "tmpfs", "/tmp",
                               "tmpfs", nullptr, nullptr, mount_flags_, 0, 1000,
                               1000, 0x666, 0, 0);
    container_config_add_device(config_->get(), 'c', "/dev/foo",
                                S_IRWXU | S_IRWXG, 245, 2, 0, 0, 1000, 1001, 1,
                                1, 0);
    // test dynamic minor on /dev/null
    container_config_add_device(config_->get(), 'c', "/dev/null",
                                S_IRWXU | S_IRWXG, 1, -1, 0, 1, 1000, 1001, 1,
                                1, 0);
    static const char* kNamespaces[] = {
        "cgroup", "ipc", "mount", "network", "pid", "user",
    };
    container_config_namespaces(config_->get(), kNamespaces,
                                std::size(kNamespaces));

    container_config_set_cpu_shares(config_->get(), kTestCpuShares);
    container_config_set_cpu_cfs_params(config_->get(), kTestCpuQuota,
                                        kTestCpuPeriod);
    /* Invalid params, so this won't be applied. */
    container_config_set_cpu_rt_params(config_->get(), 20000, 20000);

    base::FilePath rundir;
    ASSERT_TRUE(base::CreateTemporaryDirInDir(temp_dir_.GetPath(),
                                              "container_test_run", &rundir));
    container_.reset(new Container("containerUT", rundir));
    ASSERT_NE(nullptr, container_.get());
  }

  void TearDown() override {
    container_.reset();
    config_.reset();

    ASSERT_TRUE(temp_dir_.Delete());
    delete g_mock_posix_state;
    g_mock_posix_state = nullptr;
    libcontainer::Cgroup::SetCgroupFactoryForTesting(nullptr);
    delete g_mock_cgroup_state;
    delete g_mock_minijail_state;
    g_mock_minijail_state = nullptr;
  }

 protected:
  const Config* config() const { return config_.get(); }

  std::unique_ptr<Config> config_;
  std::unique_ptr<Container> container_;
  int mount_flags_;
  base::FilePath rootfs_;

 private:
  base::ScopedTempDir temp_dir_;
};

TEST_F(ContainerTest, TestMountTmpStart) {
  ASSERT_EQ(0, container_start(container_->get(), config_->get()));
  ASSERT_EQ(2, g_mock_posix_state->mount_args.size());
  EXPECT_EQ(false, g_mock_posix_state->mount_args[1].outside_mount);
  EXPECT_STREQ("tmpfs", g_mock_posix_state->mount_args[1].source.c_str());
  EXPECT_STREQ("/tmp",
               g_mock_posix_state->mount_args[1].target.value().c_str());
  EXPECT_STREQ("tmpfs",
               g_mock_posix_state->mount_args[1].filesystemtype.c_str());
  EXPECT_EQ(g_mock_posix_state->mount_args[1].mountflags,
            static_cast<unsigned long>(mount_flags_));
  EXPECT_EQ(nullptr, g_mock_posix_state->mount_args[1].data);

  EXPECT_EQ(1, g_mock_minijail_state->ipc_called_count);
  EXPECT_EQ(1, g_mock_minijail_state->vfs_called_count);
  EXPECT_EQ(1, g_mock_minijail_state->net_called_count);
  EXPECT_EQ(1, g_mock_minijail_state->pids_called_count);
  EXPECT_EQ(1, g_mock_minijail_state->user_called_count);
  EXPECT_EQ(1, g_mock_minijail_state->cgroups_called_count);
  EXPECT_EQ(1, g_mock_minijail_state->run_as_init_called_count);
  EXPECT_EQ(1, g_mock_cgroup_state->deny_all_devs_called_count);

  ASSERT_EQ(2, g_mock_cgroup_state->added_devices.size());
  EXPECT_EQ(1, g_mock_cgroup_state->added_devices[0].allow);
  EXPECT_EQ(245, g_mock_cgroup_state->added_devices[0].major);
  EXPECT_EQ(2, g_mock_cgroup_state->added_devices[0].minor);
  EXPECT_EQ(1, g_mock_cgroup_state->added_devices[0].read);
  EXPECT_EQ(1, g_mock_cgroup_state->added_devices[0].write);
  EXPECT_EQ(0, g_mock_cgroup_state->added_devices[0].modify);
  EXPECT_EQ('c', g_mock_cgroup_state->added_devices[0].type);

  EXPECT_EQ(1, g_mock_cgroup_state->added_devices[1].allow);
  EXPECT_EQ(1, g_mock_cgroup_state->added_devices[1].major);
  EXPECT_EQ(-1, g_mock_cgroup_state->added_devices[1].minor);
  EXPECT_EQ(1, g_mock_cgroup_state->added_devices[1].read);
  EXPECT_EQ(1, g_mock_cgroup_state->added_devices[1].write);
  EXPECT_EQ(0, g_mock_cgroup_state->added_devices[1].modify);
  EXPECT_EQ('c', g_mock_cgroup_state->added_devices[1].type);

  EXPECT_EQ(1, g_mock_cgroup_state->set_cpu_shares_count);
  EXPECT_EQ(kTestCpuShares, container_config_get_cpu_shares(config_->get()));
  EXPECT_EQ(1, g_mock_cgroup_state->set_cpu_quota_count);
  EXPECT_EQ(kTestCpuQuota, container_config_get_cpu_quota(config_->get()));
  EXPECT_EQ(1, g_mock_cgroup_state->set_cpu_period_count);
  EXPECT_EQ(kTestCpuPeriod, container_config_get_cpu_period(config_->get()));
  EXPECT_EQ(0, g_mock_cgroup_state->set_cpu_rt_runtime_count);
  EXPECT_EQ(0, container_config_get_cpu_rt_runtime(config_->get()));
  EXPECT_EQ(0, g_mock_cgroup_state->set_cpu_rt_period_count);
  EXPECT_EQ(0, container_config_get_cpu_rt_period(config_->get()));

  ASSERT_NE(std::string(), g_mock_minijail_state->alt_syscall_table);
  EXPECT_EQ("testsyscalltable", g_mock_minijail_state->alt_syscall_table);

  EXPECT_EQ(0, container_wait(container_->get()));
  EXPECT_EQ(1, g_mock_minijail_state->wait_called_count);
  EXPECT_EQ(1, g_mock_minijail_state->reset_signal_mask_called_count);
  EXPECT_EQ(1, g_mock_minijail_state->reset_signal_handlers_called_count);
  EXPECT_EQ(0, g_mock_minijail_state->set_supplementary_gids_called_count);
}

TEST_F(ContainerTest, TestKillContainer) {
  ASSERT_EQ(0, container_start(container_->get(), config_->get()));
  EXPECT_EQ(0, container_kill(container_->get()));
  EXPECT_EQ(std::vector<int>{SIGKILL}, g_mock_posix_state->kill_sigs);
  EXPECT_EQ(1, g_mock_minijail_state->wait_called_count);
}

// Does the same as LibcontainerTest.DumpConfig but with more configuration
// parameters similar to the production.
TEST_F(ContainerTest, DumpConfig) {
  struct container_config* config = this->config()->get();
  ASSERT_NE(nullptr, config);
  std::unique_ptr<char, decltype(&free)> config_str(
      container_config_dump(config, true /* sort_vector */), free);
  ASSERT_NE(nullptr, config_str.get());
  EXPECT_NE(0U, strlen(config_str.get()));
  EXPECT_LT(1U, base::SplitString(config_str.get(), "\n", base::KEEP_WHITESPACE,
                                  base::SPLIT_WANT_NONEMPTY)
                    .size());
}

}  // namespace libcontainer

// libc stubs so the UT doesn't need root to call mount, etc.
extern "C" {

extern decltype(chmod) __real_chmod;
int __wrap_chmod(const char* path, mode_t mode) {
  if (!libcontainer::g_mock_posix_state)
    return __real_chmod(path, mode);
  return 0;
}

extern decltype(chown) __real_chown;
int __wrap_chown(const char* path, uid_t owner, gid_t group) {
  if (!libcontainer::g_mock_posix_state)
    return __real_chown(path, owner, group);
  return 0;
}

extern decltype(getuid) __real_getuid;
uid_t __wrap_getuid(void) {
  if (!libcontainer::g_mock_posix_state)
    return __real_getuid();
  return 0;
}

extern decltype(kill) __real_kill;
int __wrap_kill(pid_t pid, int sig) {
  if (!libcontainer::g_mock_posix_state)
    return __real_kill(pid, sig);
  libcontainer::g_mock_posix_state->kill_sigs.push_back(sig);
  return 0;
}

extern decltype(mkdir) __real_mkdir;
int __wrap_mkdir(const char* pathname, mode_t mode) {
  if (!libcontainer::g_mock_posix_state)
    return __real_mkdir(pathname, mode);
  return 0;
}

extern decltype(mkdtemp) __real_mkdtemp;
char* __wrap_mkdtemp(char* template_string) {
  if (!libcontainer::g_mock_posix_state)
    return __real_mkdtemp(template_string);
  libcontainer::g_mock_posix_state->mkdtemp_root =
      base::FilePath(template_string);
  return template_string;
}

extern decltype(mount) __real_mount;
int __wrap_mount(const char* source,
                 const char* target,
                 const char* filesystemtype,
                 unsigned long mountflags,
                 const void* data) {
  if (!libcontainer::g_mock_posix_state)
    return __real_mount(source, target, filesystemtype, mountflags, data);

  libcontainer::g_mock_posix_state->mount_args.emplace_back(
      libcontainer::MockPosixState::MountArgs{source, base::FilePath(target),
                                              filesystemtype, mountflags, data,
                                              true});
  return 0;
}

extern decltype(rmdir) __real_rmdir;
int __wrap_rmdir(const char* pathname) {
  if (!libcontainer::g_mock_posix_state)
    return __real_rmdir(pathname);
  return 0;
}

extern decltype(umount) __real_umount;
int __wrap_umount(const char* target) {
  if (!libcontainer::g_mock_posix_state)
    return __real_umount(target);
  return 0;
}

extern decltype(umount2) __real_umount2;
int __wrap_umount2(const char* target, int flags) {
  if (!libcontainer::g_mock_posix_state)
    return __real_umount2(target, flags);
  return 0;
}

extern decltype(unlink) __real_unlink;
int __wrap_unlink(const char* pathname) {
  if (!libcontainer::g_mock_posix_state)
    return __real_unlink(pathname);
  return 0;
}

extern decltype(mknod) __real_mknod;
int __wrap_mknod(const char* pathname, mode_t mode, dev_t dev) {
  if (!libcontainer::g_mock_posix_state)
    return __real_mknod(pathname, mode, dev);
  return 0;
}

extern decltype(stat) __real_stat;
int __wrap_stat(const char* path, struct stat* buf) {
  if (!libcontainer::g_mock_posix_state)
    return __real_stat(path, buf);
  buf->st_rdev = libcontainer::g_mock_posix_state->stat_rdev_ret;
  return 0;
}

extern decltype(setns) __real_setns;
int __wrap_setns(int fd, int nstype) {
  if (!libcontainer::g_mock_posix_state)
    return __real_setns(fd, nstype);
  return 0;
}

/* Minijail stubs */
struct minijail* minijail_new(void) {
  return (struct minijail*)0x55;
}

void minijail_destroy(struct minijail* j) {}

int minijail_mount_with_data(struct minijail* j,
                             const char* source,
                             const char* target,
                             const char* filesystemtype,
                             unsigned long mountflags,
                             const char* data) {
  libcontainer::g_mock_posix_state->mount_args.emplace_back(
      libcontainer::MockPosixState::MountArgs{source, base::FilePath(target),
                                              filesystemtype, mountflags, data,
                                              false});
  return 0;
}

void minijail_namespace_user_disable_setgroups(struct minijail* j) {}

void minijail_namespace_vfs(struct minijail* j) {
  ++libcontainer::g_mock_minijail_state->vfs_called_count;
}

void minijail_namespace_ipc(struct minijail* j) {
  ++libcontainer::g_mock_minijail_state->ipc_called_count;
}

void minijail_namespace_net(struct minijail* j) {
  ++libcontainer::g_mock_minijail_state->net_called_count;
}

void minijail_namespace_pids(struct minijail* j) {
  ++libcontainer::g_mock_minijail_state->pids_called_count;
}

void minijail_namespace_user(struct minijail* j) {
  ++libcontainer::g_mock_minijail_state->user_called_count;
}

void minijail_namespace_cgroups(struct minijail* j) {
  ++libcontainer::g_mock_minijail_state->cgroups_called_count;
}

int minijail_uidmap(struct minijail* j, const char* uidmap) {
  return 0;
}

int minijail_gidmap(struct minijail* j, const char* gidmap) {
  return 0;
}

int minijail_enter_pivot_root(struct minijail* j, const char* dir) {
  return 0;
}

void minijail_run_as_init(struct minijail* j) {
  ++libcontainer::g_mock_minijail_state->run_as_init_called_count;
}

int minijail_run_pid_pipes_no_preload(struct minijail* j,
                                      const char* filename,
                                      char* const argv[],
                                      pid_t* pchild_pid,
                                      int* pstdin_fd,
                                      int* pstdout_fd,
                                      int* pstderr_fd) {
  libcontainer::g_mock_minijail_state->pid = fork();
  if (libcontainer::g_mock_minijail_state->pid == -1)
    return libcontainer::g_mock_minijail_state->pid;

  if (libcontainer::g_mock_minijail_state->pid == 0) {
    for (minijail_hook_event_t event :
         {MINIJAIL_HOOK_EVENT_PRE_CHROOT, MINIJAIL_HOOK_EVENT_PRE_DROP_CAPS,
          MINIJAIL_HOOK_EVENT_PRE_EXECVE}) {
      auto it = libcontainer::g_mock_minijail_state->hooks.find(event);
      if (it == libcontainer::g_mock_minijail_state->hooks.end())
        continue;
      for (auto& hook : it->second) {
        int rc = hook.Run();
        if (rc)
          _exit(rc);
      }
    }
    _exit(0);
  }

  *pchild_pid = libcontainer::g_mock_minijail_state->pid;
  return 0;
}

int minijail_write_pid_file(struct minijail* j, const char* path) {
  return 0;
}

int minijail_wait(struct minijail* j) {
  ++libcontainer::g_mock_minijail_state->wait_called_count;
  int status;
  if (HANDLE_EINTR(
          waitpid(libcontainer::g_mock_minijail_state->pid, &status, 0)) < 0) {
    PLOG(ERROR) << "Failed to wait for minijail";
    return -errno;
  }
  if (!WIFEXITED(status)) {
    LOG(ERROR) << "minijail terminated abnormally: " << std::hex << status;
    return -ECANCELED;
  }
  // Exit status gets truncated to 8 bits. This should sign-extend it so that
  // any negative values we passed are preserved.
  return static_cast<int8_t>(WEXITSTATUS(status));
}

int minijail_use_alt_syscall(struct minijail* j, const char* table) {
  libcontainer::g_mock_minijail_state->alt_syscall_table = table;
  return 0;
}

int minijail_add_to_cgroup(struct minijail* j, const char* cg_path) {
  return 0;
}

int minijail_forward_signals(struct minijail* j) {
  return 0;
}

void minijail_reset_signal_mask(struct minijail* j) {
  ++libcontainer::g_mock_minijail_state->reset_signal_mask_called_count;
}

void minijail_reset_signal_handlers(struct minijail* j) {
  ++libcontainer::g_mock_minijail_state->reset_signal_handlers_called_count;
}

void minijail_skip_remount_private(struct minijail* j) {}

int minijail_preserve_fd(struct minijail* j, int parent_fd, int child_fd) {
  return 0;
}

int minijail_add_hook(struct minijail* j,
                      minijail_hook_t hook,
                      void* payload,
                      minijail_hook_event_t event) {
  auto it = libcontainer::g_mock_minijail_state->hooks.insert(
      std::make_pair(event, std::vector<libcontainer::MinijailHookCallback>()));
  it.first->second.emplace_back(
      base::BindRepeating(hook, base::Unretained(payload)));
  return 0;
}

void minijail_close_open_fds(struct minijail* j) {}

void minijail_set_supplementary_gids(struct minijail* j,
                                     size_t size,
                                     const gid_t* list) {
  ++libcontainer::g_mock_minijail_state->set_supplementary_gids_called_count;
}

}  // extern "C"
