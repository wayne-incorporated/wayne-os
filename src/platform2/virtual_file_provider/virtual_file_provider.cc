// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sys/vfs.h>

#include <memory>
#include <optional>
#include <utility>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/functional/bind.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/message_loop/message_pump_type.h>
#include <base/posix/eintr_wrapper.h>
#include <base/threading/platform_thread.h>
#include <base/threading/thread.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "virtual_file_provider/fuse_main.h"
#include "virtual_file_provider/service.h"
#include "virtual_file_provider/util.h"

namespace virtual_file_provider {

namespace {

// Service thread handles D-Bus method calls.
class ServiceThread : public base::Thread {
 public:
  ServiceThread(const base::FilePath& fuse_mount_path, SizeMap* size_map)
      : Thread("Service thread"),
        fuse_mount_path_(fuse_mount_path),
        service_(std::make_unique<Service>(fuse_mount_path, size_map)) {}
  ServiceThread(const ServiceThread&) = delete;
  ServiceThread& operator=(const ServiceThread&) = delete;

  ~ServiceThread() override { Stop(); }

  Service* service() { return service_.get(); }

 protected:
  // base::Thread overrides:
  void Init() override {
    CHECK(WaitForFuseMount());
    CHECK(ClearCapabilities());
    CHECK(service_->Initialize());
  }

  void CleanUp() override {
    service_.reset();  // Must be destructed on the same thread as Initialize().
  }

 private:
  // Waits for the FUSE mount to get ready.
  bool WaitForFuseMount() {
    constexpr int kMaxRetryCount = 3000;
    constexpr base::TimeDelta kRetryInterval = base::Milliseconds(1);

    for (int retry_count = 0; retry_count < kMaxRetryCount; ++retry_count) {
      struct statfs buf = {};
      if (HANDLE_EINTR(statfs(fuse_mount_path_.value().c_str(), &buf)) < 0) {
        PLOG(ERROR) << "statfs() failed.";
        return false;
      }
      // Compare with FUSE_SUPER_MAGIC (defined in <kernel>/fs/fuse/inode.c).
      if (buf.f_type == 0x65735546)
        return true;

      base::PlatformThread::Sleep(kRetryInterval);
    }
    LOG(ERROR) << "Timed out while waiting for FUSE mount.";
    return false;
  }

  const base::FilePath fuse_mount_path_;
  std::unique_ptr<Service> service_;
};

class FuseMainDelegateImpl : public FuseMainDelegate {
 public:
  FuseMainDelegateImpl(ServiceThread* service_thread, SizeMap* size_map)
      : service_thread_(service_thread), size_map_(size_map) {}
  FuseMainDelegateImpl(const FuseMainDelegateImpl&) = delete;
  FuseMainDelegateImpl& operator=(const FuseMainDelegateImpl&) = delete;

  ~FuseMainDelegateImpl() override = default;

  // FuseMainDelegate overrides:
  int64_t GetSize(const std::string& id) override;
  void HandleReadRequest(const std::string& id,
                         int64_t offset,
                         int64_t size,
                         base::ScopedFD fd) override;
  void NotifyIdReleased(const std::string& id) override;

 private:
  ServiceThread* const service_thread_;
  SizeMap* const size_map_;
};

int64_t FuseMainDelegateImpl::GetSize(const std::string& id) {
  return size_map_->GetSize(id);
}

void FuseMainDelegateImpl::HandleReadRequest(const std::string& id,
                                             int64_t offset,
                                             int64_t size,
                                             base::ScopedFD fd) {
  service_thread_->task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          &Service::SendReadRequest,
          // This is safe as service_thread outlives the FUSE main loop.
          base::Unretained(service_thread_->service()), id, offset, size,
          std::move(fd)));
}

void FuseMainDelegateImpl::NotifyIdReleased(const std::string& id) {
  if (!size_map_->Erase(id)) {
    LOG(ERROR) << "Invalid ID " << id;
    return;
  }
  service_thread_->task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          &Service::SendIdReleased,
          // This is safe as service_thread outlives the FUSE main loop.
          base::Unretained(service_thread_->service()), id));
}

}  // namespace

}  // namespace virtual_file_provider

constexpr char kUsage[] =
    "virtual-file-provider daemon\n"
    "Usage: virtual-file-provider [flags]";

int main(int argc, char** argv) {
  DEFINE_string(path, "/mnt", "Set up a FUSE mount at this path");
  DEFINE_int32(uid, -1, "All FUSE files/dirs will be owned by this user id");
  DEFINE_int32(gid, -1, "All FUSE files/dirs will be owned by this group id");
  brillo::FlagHelper::Init(argc, argv, kUsage);

  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);
  base::AtExitManager at_exit_manager;

  base::FilePath fuse_mount_path(FLAGS_path);
  virtual_file_provider::SizeMap size_map;

  // Run D-Bus service on the service thread.
  virtual_file_provider::ServiceThread service_thread(fuse_mount_path,
                                                      &size_map);
  base::Thread::Options options;
  options.message_pump_type = base::MessagePumpType::IO;
  service_thread.StartWithOptions(std::move(options));

  // Enter the FUSE main loop.
  virtual_file_provider::FuseMainDelegateImpl delegate(&service_thread,
                                                       &size_map);
  std::optional<uid_t> userId =
      FLAGS_uid >= 0 ? std::make_optional(FLAGS_uid) : std::nullopt;
  std::optional<gid_t> groupId =
      FLAGS_gid >= 0 ? std::make_optional(FLAGS_gid) : std::nullopt;
  return virtual_file_provider::FuseMain(fuse_mount_path, &delegate, userId,
                                         groupId);
}
