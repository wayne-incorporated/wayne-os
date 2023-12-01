// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/seneschal/service.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mntent.h>
#include <signal.h>
#include <stdint.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <linux/vm_sockets.h>  // needs to come after sys/socket.h

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/stl_util.h>
#include <base/strings/strcat.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_runner.h>
#include <base/time/time.h>
#include <brillo/file_utils.h>
#include <chromeos/dbus/service_constants.h>
#include <chromeos/libminijail.h>
#include <chromeos/scoped_minijail.h>
#include <seneschal/proto_bindings/seneschal_service.pb.h>

using std::string;

namespace vm_tools {
namespace seneschal {
namespace {
// Path to the runtime directory where we will create server jails.
constexpr char kRuntimeDir[] = "/run/seneschal";

// The chronos uid and gid.  These are used for file system access.
constexpr uid_t kChronosUid = 1000;
constexpr gid_t kChronosGid = 1000;

// Access to android files requires android-everybody gid.
constexpr gid_t kAndroidEverybodyGid = 665357;
constexpr gid_t kSupplementaryGroups[] = {kAndroidEverybodyGid};

// The uid used for authenticating with DBus.
constexpr uid_t kDbusAuthUid = 20115;

// How long we should wait for a server process to exit.
constexpr base::TimeDelta kServerExitTimeout = base::Seconds(2);

// Path to the 9p server.
constexpr char kServerPath[] = "/usr/bin/9s";
constexpr char kServerRoot[] = "/fsroot";
constexpr char kSeccompPolicyPath[] = "/usr/share/policy/9s-seccomp.policy";

// Static prefix of SmbFs mount names.
constexpr char kSmbFsMountNamePrefix[] = "smbfs-";

// Static prefix of GuestOS mount names.
constexpr char kGuestOsMountNamePrefix[] = "guestos+";

// Max number of open files allowed per server.
constexpr rlim_t kMaxOpenFiles = 64 * 1024;

// `mkdir -p`, essentially.  Reimplement all of base::CreateDirectory because
// we want mode 0755 instead of mode 0700.
bool MkdirRecursively(const base::FilePath& full_path) {
  if (!full_path.IsAbsolute()) {
    LOG(INFO) << "Relative paths are not supported: " << full_path.value();
    return false;
  }

  // Collect a list of all parent directories.
  std::vector<std::string> components = full_path.GetComponents();
  DCHECK(!components.empty());

  base::ScopedFD fd(open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  if (!fd.is_valid())
    return false;

  // Iterate through the parents and create the missing ones. '+ 1' is for
  // skipping "/".
  for (std::vector<std::string>::const_iterator i = components.begin() + 1;
       i != components.end(); ++i) {
    // Try to create the directory. Note that Chromium's MkdirRecursively() uses
    // 0700, but we use 0755.
    if (mkdirat(fd.get(), i->c_str(), 0755) != 0) {
      if (errno != EEXIST) {
        PLOG(ERROR) << "Failed to mkdirat " << *i
                    << ": full_path=" << full_path.value();
        return false;
      }

      // The path already exists. Make sure that the path is a directory.
      struct stat st;
      if (fstatat(fd.get(), i->c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) {
        PLOG(ERROR) << "Failed to fstatat " << *i
                    << ": full_path=" << full_path.value();
        return false;
      }
      if (!S_ISDIR(st.st_mode)) {
        LOG(ERROR) << *i << " is not a directory: st_mode=" << st.st_mode
                   << ", full_path=" << full_path.value();
        return false;
      }
    }

    // Updates the FD so it refers to the new directory created or checked
    // above.
    const int new_fd =
        openat(fd.get(), i->c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK, 0);
    if (new_fd < 0) {
      PLOG(ERROR) << "Failed to openat " << *i
                  << ": full_path=" << full_path.value();
      return false;
    }
    fd.reset(new_fd);
    continue;
  }
  return true;
}

// Passes |method_call| to |handler| and passes the response to
// |response_sender|. If |handler| returns NULL, an empty response is created
// and sent.
void HandleSynchronousDBusMethodCall(
    base::RepeatingCallback<std::unique_ptr<dbus::Response>(dbus::MethodCall*)>
        handler,
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  std::unique_ptr<dbus::Response> response = handler.Run(method_call);
  if (!response)
    response = dbus::Response::FromMethodCall(method_call);
  std::move(response_sender).Run(std::move(response));
}

}  // namespace

Service::ServerInfo::ServerInfo(pid_t pid, base::FilePath root_dir)
    : pid_(pid) {
  CHECK(root_dir_.Set(root_dir));
}

Service::ServerInfo::ServerInfo(Service::ServerInfo&& other) noexcept
    : pid_(other.pid_) {
  CHECK(root_dir_.Set(other.root_dir_.Take()));
}

Service::ServerInfo& Service::ServerInfo::operator=(
    Service::ServerInfo&& other) noexcept {
  // Self assignment check is required.
  if (this != &other) {
    pid_ = other.pid_;
    CHECK(root_dir_.Set(other.root_dir_.Take()));
  }

  return *this;
}

Service::ServerInfo::~ServerInfo() {
  if (!root_dir_.IsValid()) {
    // Nothing to see here.
    return;
  }

  // Clean up the mounts so that we can delete the temporary directory.  An
  // error in any of these operations means that we cannot safely delete the
  // directory.  Instead the directory will get cleaned up when seneschal exits
  // as this will delete the mount namespace and all the mounts in it.
  string contents;
  if (!base::ReadFileToString(base::FilePath("/proc/self/mounts"), &contents)) {
    PLOG(ERROR) << "Unable to read contents of /proc/self/mounts; not deleting "
                << "runtime directory";
    root_dir_.Take();
    return;
  }

  std::vector<string> mounts;
  for (base::StringPiece line : base::SplitStringPiece(
           contents, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY)) {
    std::vector<base::StringPiece> mount_data = base::SplitStringPiece(
        line, " ", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
    if (mount_data.size() < 6) {
      LOG(ERROR) << "Invalid mount data: " << line;
      root_dir_.Take();
      return;
    }

    // The mount point is the second column.
    if (root_dir_.GetPath().IsParent(base::FilePath(mount_data[1]))) {
      mounts.emplace_back(mount_data[1]);
    }
  }

  // Now unmount everything in reverse order.
  for (auto iter = mounts.rbegin(), end = mounts.rend(); iter != end; ++iter) {
    if (umount(iter->c_str()) != 0) {
      PLOG(ERROR) << "Unable to unmount path; not deleting runtime directory";
      root_dir_.Take();
      return;
    }
  }
}

// static
std::unique_ptr<Service> Service::Create(base::OnceClosure quit_closure) {
  std::unique_ptr<Service> service(new Service(std::move(quit_closure)));

  if (!service->Init()) {
    service.reset();
  }

  return service;
}

Service::Service(base::OnceClosure quit_closure)
    : next_server_handle_(1),
      quit_closure_(std::move(quit_closure)),
      weak_factory_(this) {}

bool Service::Init() {
  // Set up the dbus service.
  dbus::Bus::Options opts;
  opts.bus_type = dbus::Bus::SYSTEM;
  bus_ = new dbus::Bus(std::move(opts));

  // When authenticating with DBus a client process that wants to connect to
  // the system dbus daemon sends an authentication request with its current
  // effective uid.  The dbus daemon then uses SO_PEERCRED to verify that the
  // uid of the client process matches what it claims to be.  Normally this is
  // fine but when the client process runs inside a user namespace it thinks it
  // has uid 0 inside the namespace while the dbus daemon, which runs outside
  // the namespace, thinks it has some other uid.  To deal with this we
  // temprarily change our effective uid to match the effective uid outside the
  // user namespace and then change it back once we have authenticated with the
  // dbus daemon.
  if (seteuid(kDbusAuthUid) != 0) {
    PLOG(ERROR) << "Unable to change effective uid to " << kDbusAuthUid;
    return false;
  }

  if (!bus_->Connect()) {
    LOG(ERROR) << "Failed to connect to system bus";
    return false;
  }

  if (seteuid(0) != 0) {
    PLOG(ERROR) << "Unable to change effective uid back to 0";
    return false;
  }

  exported_object_ =
      bus_->GetExportedObject(dbus::ObjectPath(kSeneschalServicePath));
  if (!exported_object_) {
    LOG(ERROR) << "Failed to export " << kSeneschalServicePath << " object";
    return false;
  }

  using ServiceMethod =
      std::unique_ptr<dbus::Response> (Service::*)(dbus::MethodCall*);
  const std::map<const char*, ServiceMethod> kServiceMethods = {
      {kStartServerMethod, &Service::StartServer},
      {kStopServerMethod, &Service::StopServer},
      {kSharePathMethod, &Service::SharePath},
      {kUnsharePathMethod, &Service::UnsharePath},
  };

  for (const auto& iter : kServiceMethods) {
    bool ret = exported_object_->ExportMethodAndBlock(
        kSeneschalInterface, iter.first,
        base::BindRepeating(
            &HandleSynchronousDBusMethodCall,
            base::BindRepeating(iter.second, base::Unretained(this))));
    if (!ret) {
      LOG(ERROR) << "Failed to export method " << iter.first;
      return false;
    }
  }

  if (!bus_->RequestOwnershipAndBlock(kSeneschalServiceName,
                                      dbus::Bus::REQUIRE_PRIMARY)) {
    LOG(ERROR) << "Failed to take ownership of " << kSeneschalServiceName;
    return false;
  }

  // Set up the signalfd for receiving SIGCHLD and SIGTERM.
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  sigaddset(&mask, SIGTERM);

  signal_fd_.reset(signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC));
  if (!signal_fd_.is_valid()) {
    PLOG(ERROR) << "Failed to create signalfd";
    return false;
  }

  watcher_ = base::FileDescriptorWatcher::WatchReadable(
      signal_fd_.get(),
      base::BindRepeating(&Service::OnSignalReadable, base::Unretained(this)));
  if (!watcher_) {
    LOG(ERROR) << "Failed to watch signalfd";
    return false;
  }

  // Now block signals from the normal signal handling path so that we will get
  // them via the signalfd.
  if (sigprocmask(SIG_BLOCK, &mask, nullptr) < 0) {
    PLOG(ERROR) << "Failed to block signals via sigprocmask";
    return false;
  }

  return true;
}

void Service::OnSignalReadable() {
  struct signalfd_siginfo siginfo;
  if (read(signal_fd_.get(), &siginfo, sizeof(siginfo)) != sizeof(siginfo)) {
    PLOG(ERROR) << "Failed to read from signalfd";
    return;
  }

  if (siginfo.ssi_signo == SIGCHLD) {
    HandleChildExit();
  } else if (siginfo.ssi_signo == SIGTERM) {
    HandleSigterm();
  } else {
    LOG(ERROR) << "Received unknown signal from signal fd: "
               << strsignal(siginfo.ssi_signo);
  }
}

void Service::HandleChildExit() {
  // We can't just rely on the information in the siginfo structure because
  // more than one child may have exited but only one SIGCHLD will be
  // generated.
  while (true) {
    int status;
    pid_t pid = waitpid(-1, &status, WNOHANG);
    if (pid <= 0) {
      if (pid == -1 && errno != ECHILD) {
        PLOG(ERROR) << "Unable to reap child processes";
      }
      break;
    }

    if (WIFEXITED(status)) {
      LOG(INFO) << "Process " << pid << " exited with status "
                << WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
      LOG(INFO) << "Process " << pid << " killed by signal " << WTERMSIG(status)
                << (WCOREDUMP(status) ? " (core dumped)" : "");
    } else {
      LOG(WARNING) << "Unknown exit status " << status << " for process "
                   << pid;
    }

    // See if this is a process we launched.
    for (const auto& pair : servers_) {
      if (pid == pair.second.pid()) {
        servers_.erase(pair.first);
        break;
      }
    }
  }
}

void Service::HandleSigterm() {
  LOG(INFO) << "Shutting down due to SIGTERM";

  // Close our connection to the bus.
  bus_->ShutdownAndBlock();

  // Stop the message loop.
  if (quit_closure_) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, std::move(quit_closure_));
  }
}

// Handles a request to start a new 9p server.
std::unique_ptr<dbus::Response> Service::StartServer(
    dbus::MethodCall* method_call) {
  LOG(INFO) << "Received request to start new 9p server";

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  StartServerRequest request;
  StartServerResponse response;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse StartServerRequest from message";
    response.set_failure_reason("Unable to parse protobuf");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  base::ScopedTempDir root_dir;
  if (!root_dir.CreateUniqueTempDirUnderPath(base::FilePath(kRuntimeDir))) {
    LOG(ERROR) << "Unable to create working dir for server";
    response.set_failure_reason("Unable to create working dir for server");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // Make sure the child process has permission to read the contents.
  if (chmod(root_dir.GetPath().value().c_str(), 0755) != 0) {
    PLOG(ERROR) << "Failed to change permissions for "
                << root_dir.GetPath().value();
    response.set_failure_reason(
        "Failed to change permissions for server's working dir");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // Create the directory that the server will serve to clients.  Offset the
  // root path by 1 because Append wants relative paths.
  base::FilePath client_root = root_dir.GetPath().Append(&kServerRoot[1]);
  if (mkdir(client_root.value().c_str(), 0755) != 0) {
    PLOG(ERROR) << "Unable to create server root dir";
    response.set_failure_reason("Unable to create server root dir");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // Get the listening address and any extra command line options.
  std::vector<string> args = {kServerPath, "-r", kServerRoot};

  for (const auto& idmap : request.uid_maps()) {
    args.emplace_back("--uid_map");
    args.emplace_back(
        base::StringPrintf("%u:%u", idmap.server(), idmap.client()));
  }

  for (const auto& idmap : request.gid_maps()) {
    args.emplace_back("--gid_map");
    args.emplace_back(
        base::StringPrintf("%u:%u", idmap.server(), idmap.client()));
  }

  base::ScopedFD listen_fd;
  bool valid_address = false;
  switch (request.listen_address_case()) {
    case StartServerRequest::kVsock: {
      const VsockAddress& addr = request.vsock();
      if (addr.accept_cid() < 3) {
        LOG(ERROR) << "Missing or invalid accept_cid field in vsock address: "
                   << addr.accept_cid();
        break;
      }

      args.emplace_back("--accept_cid");
      args.emplace_back(std::to_string(addr.accept_cid()));
      args.emplace_back(string("vsock:") + std::to_string(addr.port()));
      valid_address = true;
      break;
    }
    case StartServerRequest::kFd: {
      if (!reader.PopFileDescriptor(&listen_fd)) {
        LOG(ERROR) << "No fd found in incoming message";
        break;
      }

      // Clear close-on-exec as this FD needs to be passed to 9s.
      int flags = fcntl(listen_fd.get(), F_GETFD);
      if (flags == -1) {
        PLOG(ERROR) << "Failed to get flags for passed fd";
        break;
      }
      if (fcntl(listen_fd.get(), F_SETFD, flags & ~FD_CLOEXEC) == -1) {
        PLOG(ERROR) << "Failed to clear close-on-exec flag for fd";
        break;
      }

      args.emplace_back(base::StringPrintf("unix-fd:%d", listen_fd.get()));
      valid_address = true;
      break;
    }
    case StartServerRequest::kUnixAddr:
    case StartServerRequest::kNet:
      LOG(ERROR) << "Listen address not implemented: "
                 << request.listen_address_case();
      break;
    case StartServerRequest::LISTEN_ADDRESS_NOT_SET:
      LOG(ERROR) << "Listen address not set";
      break;
    default:
      LOG(ERROR) << "Unknown listen address: " << request.listen_address_case();
      break;
  }

  if (!valid_address) {
    LOG(ERROR) << "Unable to create listening address";
    response.set_failure_reason("Unable to create listening address");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::vector<const char*> argv(args.size());
  std::transform(args.begin(), args.end(), argv.begin(),
                 [](const string& arg) -> const char* { return arg.c_str(); });
  argv.emplace_back(nullptr);

  ScopedMinijail jail(minijail_new());
  if (!jail) {
    LOG(ERROR) << "Unable to create minijail";
    response.set_failure_reason("Unable to create minijail");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // Set up a new mount namespace but allow bind mounts from the parent
  // namespace to propagate into the server's namespace.
  minijail_namespace_vfs(jail.get());
  minijail_remount_mode(jail.get(), MS_SLAVE);

  // Since we are going to be in a user namespace all bind mounts have to use
  // MS_REC.
  constexpr struct {
    const char* src;
    bool writable;
  } bind_mounts[] = {
      {
          .src = "/proc",
          .writable = false,
      },
      {
          .src = "/dev/null",
          .writable = true,
      },
      {
          .src = "/dev/log",
          .writable = true,
      },
  };

  for (const auto& bind_mount : bind_mounts) {
    int flags = MS_BIND | MS_REC;
    if (!bind_mount.writable) {
      flags |= MS_RDONLY;
    }

    int ret = minijail_mount(jail.get(), bind_mount.src, bind_mount.src, "bind",
                             flags);
    if (ret < 0) {
      LOG(ERROR) << "Failed to bind mount " << bind_mount.src << ": "
                 << strerror(-ret);
      response.set_failure_reason("Unable to set up server jail");
      writer.AppendProtoAsArrayOfBytes(response);
      return dbus_response;
    }
  }

  // Add android-everybody for access to android files.
  minijail_set_supplementary_gids(jail.get(), std::size(kSupplementaryGroups),
                                  kSupplementaryGroups);
  minijail_change_uid(jail.get(), kChronosUid);
  minijail_change_gid(jail.get(), kChronosGid);

  // The process can only see what is in its root directory.
  int ret =
      minijail_enter_pivot_root(jail.get(), root_dir.GetPath().value().c_str());
  if (ret < 0) {
    LOG(ERROR) << "Unable to configure pivot_root: " << strerror(-ret);
    response.set_failure_reason("Unable to configure pivot_root");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // We will manage this process's lifetime.
  minijail_run_as_init(jail.get());

  // It doesn't need any caps or any new privileges.
  minijail_use_caps(jail.get(), 0);
  minijail_no_new_privs(jail.get());

  // Use a seccomp filter.
  minijail_log_seccomp_filter_failures(jail.get());
  minijail_parse_seccomp_filters(jail.get(), kSeccompPolicyPath);
  minijail_use_seccomp_filter(jail.get());

  // The server tends to open more fds than a regular program.
  ret =
      minijail_rlimit(jail.get(), RLIMIT_NOFILE, kMaxOpenFiles, kMaxOpenFiles);
  if (ret < 0) {
    LOG(ERROR) << "Unable to configure rlimit: " << strerror(-ret);
    response.set_failure_reason("Unable to configure minijail");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // Reset the signal mask since we block SIGCHLD and SIGTERM in this process
  // for signalfd.
  minijail_reset_signal_mask(jail.get());
  minijail_reset_signal_handlers(jail.get());

  // Launch the server.
  pid_t child_pid = 0;
  ret = minijail_run_pid(jail.get(), kServerPath,
                         const_cast<char* const*>(argv.data()), &child_pid);
  if (ret < 0) {
    LOG(ERROR) << "Unable to spawn server process: " << strerror(-ret);
    response.set_failure_reason("Unable to spawn server");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // We're done.
  LOG(INFO) << "Started server on " << root_dir.GetPath().value();

  uint32_t handle = next_server_handle_++;
  servers_.emplace(handle, ServerInfo(child_pid, root_dir.Take()));

  response.set_success(true);
  response.set_handle(handle);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

// Handles a request to stop a running 9p server.
std::unique_ptr<dbus::Response> Service::StopServer(
    dbus::MethodCall* method_call) {
  LOG(INFO) << "Received request to stop server";

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  StopServerRequest request;
  StopServerResponse response;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse StopServerRequest from message";
    response.set_failure_reason("Unable to parse protobuf");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  const auto& iter = servers_.find(request.handle());
  if (iter == servers_.end()) {
    // The server is gone.  Nothing left to do here.
    response.set_success(true);
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // Otherwise we send the process a SIGTERM and report success while lazily
  // ensuring the server will exit.  This works because we don't reuse handles
  // (unless we somehow spawn ~4 billion servers in ~2 seconds).
  if (kill(iter->second.pid(), SIGTERM) != 0 && errno != ESRCH) {
    PLOG(ERROR) << "Unable to send SIGTERM to child process";
    response.set_failure_reason("Unable to send signal to child process");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&Service::KillServer, weak_factory_.GetWeakPtr(),
                     request.handle()),
      kServerExitTimeout);

  response.set_success(true);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

// Handles a request to share a path with a running server.
std::unique_ptr<dbus::Response> Service::SharePath(
    dbus::MethodCall* method_call) {
  LOG(INFO) << "Received request to share path with server";

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  SharePathRequest request;
  SharePathResponse response;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse SharePathRequest from message";
    response.set_failure_reason("Unable to parse protobuf");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  const auto& iter = servers_.find(request.handle());
  if (iter == servers_.end()) {
    LOG(ERROR) << "Requested server does not exist";
    response.set_failure_reason("Requested server does not exist");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // Validate path.
  base::FilePath path(request.shared_path().path());
  if (path.IsAbsolute() || path.ReferencesParent() ||
      path.BaseName().value() == ".") {
    LOG(ERROR) << "Requested path references parent, is absolute, or ends "
               << "with ./";
    response.set_failure_reason(
        "Path must be relative and cannot reference parent components nor end "
        "with \".\"");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // Validate owner_id.
  base::FilePath owner_id(request.owner_id());
  bool owner_id_required =
      request.storage_location() == SharePathRequest::DOWNLOADS ||
      request.storage_location() == SharePathRequest::MY_FILES ||
      request.storage_location() == SharePathRequest::LINUX_FILES ||
      request.storage_location() == SharePathRequest::GUEST_OS_FILES;
  if (owner_id.ReferencesParent() || owner_id.BaseName() != owner_id ||
      (owner_id_required && owner_id.value().size() == 0)) {
    LOG(ERROR) << "owner_id references parent, or is "
                  "more than 1 component, or is required and not populated";
    response.set_failure_reason("owner_id must be a single valid component");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // Validate drivefs_mount_name.
  base::FilePath drivefs_mount_name(request.drivefs_mount_name());
  bool drivefs_mount_name_required =
      request.storage_location() == SharePathRequest::DRIVEFS_MY_DRIVE ||
      request.storage_location() == SharePathRequest::DRIVEFS_TEAM_DRIVES ||
      request.storage_location() == SharePathRequest::DRIVEFS_COMPUTERS ||
      request.storage_location() == SharePathRequest::DRIVEFS_FILES_BY_ID ||
      request.storage_location() ==
          SharePathRequest::DRIVEFS_SHORTCUT_TARGETS_BY_ID;
  if (drivefs_mount_name_required &&
      (drivefs_mount_name.ReferencesParent() ||
       drivefs_mount_name.BaseName() != drivefs_mount_name ||
       !base::StartsWith(drivefs_mount_name.value(), "drivefs-",
                         base::CompareCase::SENSITIVE))) {
    LOG(ERROR) << "drivefs_mount_name references parent, or is "
                  "more than 1 component, or is required and not populated";
    response.set_failure_reason(
        "drivefs_mount_name must be a single valid component");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // Validate smbfs_mount_name and set smbfs_dst_prefix.
  base::FilePath smbfs_mount_name(request.smbfs_mount_name());
  std::string smbfs_dst_prefix;
  if (request.storage_location() == SharePathRequest::SMBFS) {
    if (smbfs_mount_name.ReferencesParent() ||
        smbfs_mount_name.BaseName() != smbfs_mount_name ||
        !base::StartsWith(smbfs_mount_name.value(), kSmbFsMountNamePrefix,
                          base::CompareCase::SENSITIVE)) {
      LOG(ERROR) << "smbfs_mount_name references parent, or is more than 1 "
                    "component, or is not populated";
      response.set_failure_reason(
          "smbfs_mount_name must be a single valid component");
      writer.AppendProtoAsArrayOfBytes(response);
      return dbus_response;
    }

    // Paths within SMB shares are all mounted within a parent directory
    // that is named based on the share ID itself.
    smbfs_dst_prefix = smbfs_mount_name.value().substr(
        std::string(kSmbFsMountNamePrefix).size());
  }

  // Validate guest_os_mount_name and set guest_os_dst_prefix.
  base::FilePath guest_os_mount_name(request.guest_os_mount_name());
  std::string guest_os_dst_prefix;
  if (request.storage_location() == SharePathRequest::GUEST_OS_FILES) {
    if (guest_os_mount_name.ReferencesParent() ||
        guest_os_mount_name.BaseName() != guest_os_mount_name ||
        !base::StartsWith(
            guest_os_mount_name.value(),
            base::StrCat({kGuestOsMountNamePrefix, owner_id.value(), "+"}),
            base::CompareCase::SENSITIVE)) {
      LOG(ERROR) << "guest_os_mount_name references parent, or is more than 1 "
                    "component, or is not populated";
      response.set_failure_reason(
          "guest_os_mount_name must be a single valid component");
      writer.AppendProtoAsArrayOfBytes(response);
      return dbus_response;
    }
    // Once we strip the prefix and owner id we're left with an encoded vm name
    // and container name, which gives us a per-guest identifier. Use this as
    // the root for sharing that guests's folders in to the target.
    guest_os_dst_prefix = guest_os_mount_name.value().substr(
        strlen(kGuestOsMountNamePrefix) + owner_id.value().length() + 1);
  }

  // Build the source and destination directories.
  base::FilePath src;
  base::FilePath dst =
      iter->second.root_dir().GetPath().Append(&kServerRoot[1]);

  // Used later to strip out the prefix from the destination so that we return
  // the relative path to the shared target.
  const size_t prefix_len = dst.value().size() + 1;

  switch (request.storage_location()) {
    case SharePathRequest::DOWNLOADS:
      src = base::FilePath("/home/user/").Append(owner_id).Append("Downloads");
      dst = dst.Append("MyFiles").Append("Downloads");
      break;
    case SharePathRequest::DRIVEFS_MY_DRIVE:
      src = base::FilePath("/media/fuse/")
                .Append(drivefs_mount_name)
                .Append("root");
      dst = dst.Append("GoogleDrive").Append("MyDrive");
      break;
    case SharePathRequest::DRIVEFS_TEAM_DRIVES:
      src = base::FilePath("/media/fuse/")
                .Append(drivefs_mount_name)
                .Append("team_drives");
      dst = dst.Append("GoogleDrive").Append("SharedDrives");
      break;
    case SharePathRequest::DRIVEFS_COMPUTERS:
      src = base::FilePath("/media/fuse/")
                .Append(drivefs_mount_name)
                .Append("Computers");
      dst = dst.Append("GoogleDrive").Append("Computers");
      break;
    case SharePathRequest::DRIVEFS_FILES_BY_ID:
      src = base::FilePath("/media/fuse/")
                .Append(drivefs_mount_name)
                .Append(".files-by-id");
      dst = dst.Append("GoogleDrive").Append("SharedWithMe");
      break;
    case SharePathRequest::DRIVEFS_SHORTCUT_TARGETS_BY_ID:
      src = base::FilePath("/media/fuse/")
                .Append(drivefs_mount_name)
                .Append(".shortcut-targets-by-id");
      dst = dst.Append("GoogleDrive").Append("ShortcutsSharedWithMe");
      break;
    // Note: DriveFs .Trash directory must not ever be shared since it would
    // allow linux apps to make permanent deletes to Drive.
    case SharePathRequest::REMOVABLE:
      src = base::FilePath("/media/removable");
      dst = dst.Append("removable");
      break;
    case SharePathRequest::MY_FILES:
      src = base::FilePath("/home/user/").Append(owner_id).Append("MyFiles");
      dst = dst.Append("MyFiles");
      break;
    case SharePathRequest::PLAY_FILES:
      src = base::FilePath("/run/arc/sdcard/write/emulated/0");
      dst = dst.Append("PlayFiles");
      break;
    case SharePathRequest::PLAY_FILES_GUEST_OS:
      src = base::FilePath("/media/fuse/android_files");
      dst = dst.Append("PlayFiles");
      break;
    case SharePathRequest::LINUX_FILES:
      src = base::FilePath("/media/fuse/")
                .Append(base::JoinString(
                    {"crostini", owner_id.value(), "termina", "penguin"}, "_"));
      dst = dst.Append("LinuxFiles");
      break;
    case SharePathRequest::GUEST_OS_FILES:
      src = base::FilePath("/media/fuse/").Append(guest_os_mount_name),
      dst = dst.Append("GuestOsFiles").Append(guest_os_dst_prefix);
      break;
    case SharePathRequest::FONTS:
      src = base::FilePath("/usr/share/fonts");
      dst = dst.Append("fonts");
      break;
    case SharePathRequest::ARCHIVE:
      src = base::FilePath("/media/archive");
      dst = dst.Append("archive");
      break;
    case SharePathRequest::SMBFS:
      src = base::FilePath("/media/fuse").Append(smbfs_mount_name);
      dst = dst.Append("SMB").Append(smbfs_dst_prefix);
      break;
    default:
      LOG(ERROR) << "Unknown storage location: " << request.storage_location();
      response.set_failure_reason("Unknown storage location");
      writer.AppendProtoAsArrayOfBytes(response);
      return dbus_response;
  }

  // Get the remaining path.

  src = src.Append(path);
  if (!base::PathExists(src)) {
    LOG(ERROR) << "Requested path does not exist";
    response.set_failure_reason("Requested path does not exist");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  base::ScopedFD src_fd(brillo::OpenSafely(src, O_RDONLY | O_CLOEXEC, 0600));
  if (!src_fd.is_valid()) {
    LOG(ERROR) << "Requested path may contain symlinks or point to a "
               << "non-regular file or directory";
    response.set_failure_reason(
        "Requested path may contain symlinks or point to a non-regular "
        "file/directory");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  dst = dst.Append(path);
  // The destination directory may already exist either because one of its
  // children was shared and it was automatically created or one of its parents
  // was shared and it's already visible.
  if (!base::PathExists(dst)) {
    // First create everything up to the basename.
    if (!MkdirRecursively(dst.DirName())) {
      response.set_failure_reason(
          "Failed to create parent directory for destination");
      writer.AppendProtoAsArrayOfBytes(response);
      return dbus_response;
    }

    // Then create a file or directory, as necessary.
    struct stat info;
    if (fstat(src_fd.get(), &info) != 0) {
      PLOG(ERROR) << "Unable to stat source path";
      response.set_failure_reason("Unable to stat source path");
      writer.AppendProtoAsArrayOfBytes(response);
      return dbus_response;
    }

    if (S_ISDIR(info.st_mode)) {
      if (mkdir(dst.value().c_str(), 0700) != 0 && errno != EEXIST) {
        PLOG(ERROR) << "Unable to create destination directory";
        response.set_failure_reason("Unable to create destination directory");
        writer.AppendProtoAsArrayOfBytes(response);
        return dbus_response;
      }
    } else {
      base::ScopedFD file(open(dst.value().c_str(),
                               O_WRONLY | O_CREAT | O_CLOEXEC | O_NONBLOCK,
                               0600));
      if (!file.is_valid()) {
        PLOG(ERROR) << "Unable to create destination file";
        response.set_failure_reason("Unable to create destination file");
        writer.AppendProtoAsArrayOfBytes(response);
        return dbus_response;
      }
    }
  }

  // Do the mount.
  unsigned long flags = MS_BIND | MS_REC;  // NOLINT(runtime/int)
  string proc_path = base::StringPrintf("/proc/self/fd/%d", src_fd.get());
  const char* source = proc_path.c_str();
  const char* target = dst.value().c_str();
  if (mount(source, target, "none", flags, nullptr) != 0) {
    PLOG(ERROR) << "Unable to create bind mount";
    response.set_failure_reason("Unable to create bind mount");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // Left out because we do not currently have permissions to change the flags
  // of a mount, even if it reduces privilege.  Thanks, Torvalds.
  // We cannot specify `MS_BIND` and `MS_RDONLY` in the same mount call so
  // we have remount the path to make it read-only.
  // if (!request.shared_path().writable()) {
  //   flags |= MS_REMOUNT | MS_RDONLY;
  //   if (mount(source, target, "none", flags, nullptr) != 0) {
  //     PLOG(ERROR) << "Unable to remount read-only";

  //     // Unmount the target so that we don't leak it in a writable state.
  //     // There's not a lot we can do in case of failure here.
  //     umount2(target, MNT_DETACH);
  //     // TODO: also delete the path

  //     response.set_failure_reason("Unable to remount read-only");
  //     writer.AppendProtoAsArrayOfBytes(response);
  //     return dbus_response;
  //   }
  // }

  response.set_success(true);
  response.set_path(dst.value().substr(prefix_len));
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

// Handles a request to unshare a path with a running server.
std::unique_ptr<dbus::Response> Service::UnsharePath(
    dbus::MethodCall* method_call) {
  LOG(INFO) << "Received request to unshare path with server";

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  UnsharePathRequest request;
  UnsharePathResponse response;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse UnsharePathRequest from message";
    response.set_failure_reason("Unable to parse protobuf");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  const auto& iter = servers_.find(request.handle());
  if (iter == servers_.end()) {
    LOG(ERROR) << "Requested server does not exist";
    response.set_failure_reason("Requested server does not exist");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // Validate path.
  base::FilePath path(request.path());
  if (path.empty() || path.IsAbsolute() || path.ReferencesParent() ||
      path.BaseName().value() == ".") {
    LOG(ERROR) << "Requested path is empty, references parent, is absolute, or "
                  "ends with ./";
    response.set_failure_reason(
        "Path must be non-empty, relative, cannot reference parent components, "
        "nor end with \".\"");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  base::FilePath server_root =
      iter->second.root_dir().GetPath().Append(&kServerRoot[1]);
  base::FilePath dst = server_root.Append(path);
  base::FilePath my_files = server_root.Append("MyFiles");
  base::FilePath my_files_downloads = my_files.Append("Downloads");
  // There is a race when unmounting a volume with shares (crbug.com/1132707)
  // and |dst| may not exist. It is also expected (crbug.com/1133621) that |dst|
  // will not exist when removing a share from settings when the volume is not
  // mounted. We will log such cases, but continue and remove any mounts and
  // clean up empty mount points.
  if (!base::PathExists(dst)) {
    LOG(WARNING) << "Unshare path does not exist";
  }

  // After unmounting, clean up empty directories.  Assume at first that we can
  // delete the topmost directory under server_root, but validate / modify this
  // path to ensure it does not contain any other mount points.  E.g. if
  // dst=<server_root>/MyFiles/a/b1/c/d, then assume we can delete
  // <server_root>/MyFiles, but if another mount exists at or under
  // <server_root>/MyFiles/a/b2, then we only delete from
  // <server_root>/MyFiles/a/b1.
  base::FilePath path_to_delete = server_root;
  std::vector<std::string> server_root_components = server_root.GetComponents();
  size_t path_to_delete_depth = server_root_components.size();
  std::vector<std::string> dst_components = dst.GetComponents();

  // Ensure path is listed in /proc/self/mounts and has no parents within
  // server_root.
  bool path_is_mount = false;
  bool path_has_parent_mount = false;
  base::ScopedFILE mountinfo(fopen("/proc/self/mounts", "r"));
  if (!mountinfo) {
    LOG(ERROR) << "Failed to open /proc/self/mounts";
    response.set_failure_reason("Failed to open /proc/self/mounts");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  // List of paths to be unmounted includes path and any children.
  std::vector<base::FilePath> mount_points;
  char buf[1024 + 4];
  struct mntent entry;
  while (getmntent_r(mountinfo.get(), &entry, buf, sizeof(buf)) != nullptr) {
    base::FilePath mount_point(entry.mnt_dir);
    if (mount_point == dst) {
      // Mount is dst.  This is expected/required that one entry will match.
      path_is_mount = true;
      mount_points.emplace_back(mount_point);
    } else if (dst.IsParent(mount_point)) {
      // Mount is a child of dst.  This is OK, we will unmount it before
      // unmounting dst.
      mount_points.emplace_back(mount_point);
    } else if (server_root.IsParent(mount_point) && mount_point.IsParent(dst)) {
      // Mount is a parent of dst.  This is an error condition and we will soon
      // fail.
      path_has_parent_mount = true;
    } else {
      // Modify path_to_delete if required so it does not contain mount_point.
      std::vector<std::string> mount_point_components =
          mount_point.GetComponents();
      for (size_t i = 0;
           i < dst_components.size() - 1 && i < mount_point_components.size() &&
           dst_components[i] == mount_point_components[i];
           ++i) {
        if (i == path_to_delete_depth) {
          path_to_delete =
              path_to_delete.Append(dst_components[path_to_delete_depth++]);
        }
      }
    }
  }
  // Set path_to_delete to have 1 more component past server_root or any path
  // common with another mount.
  path_to_delete =
      path_to_delete.Append(dst_components[path_to_delete_depth++]);

  if (!path_is_mount) {
    LOG(ERROR) << "Path is not a mount point";
    response.set_failure_reason("Path is not a mount point");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  if (path_has_parent_mount) {
    LOG(ERROR) << "Path has a parent mount point";
    response.set_failure_reason("Path has a parent mount point");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // In reverse order, unmount paths.
  for (auto iter = mount_points.rbegin(), end = mount_points.rend();
       iter != end; ++iter) {
    if (umount(iter->value().c_str()) != 0) {
      // When MyFiles is shared, its MyFiles/Downloads mount propagates. It
      // seems that the kernel does not allow us to unmount MyFiles/Downloads
      // with EINVAL, and then also fails to unmount MyFiles with EBUSY even
      // when no files are open.
      if (errno == EINVAL && dst == my_files &&
          iter->value() == my_files_downloads.value()) {
        // Ignore EINVAL when unsharing MyFiles and MyFiles/Downloads fails.
        PLOG(WARNING)
            << "Unmount MyFiles/Downloads failed with EINVAL, ignoring";
        continue;
      } else if (errno == EBUSY && iter->value() == my_files.value()) {
        // If/when unmount MyFiles fails with EBUSY, we retry with MNT_DETACH.
        PLOG(WARNING)
            << "Unmount MyFiles failed with EBUSY, attempting MNT_DETACH";
        if (umount2(iter->value().c_str(), MNT_DETACH) == 0) {
          continue;
        }
      }
      PLOG(ERROR) << "Failed to unmount";
      response.set_failure_reason("Failed to unmount");
      writer.AppendProtoAsArrayOfBytes(response);
      return dbus_response;
    }
  }

  // Remove path_to_delete.  Recursive is required to delete any children mount
  // dirs that were created prior to this path being mounted, and any empty
  // directories that were created for this mount.  Recursive delete is safe
  // since no mounts exist under this directory.
  if (!base::DeletePathRecursively(path_to_delete)) {
    LOG(ERROR) << "Delete path failed";
    response.set_failure_reason("Delete path failed");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  response.set_success(true);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

// Forcibly kills a server if it hasn't already exited.
void Service::KillServer(uint32_t handle) {
  const auto& iter = servers_.find(handle);
  if (iter != servers_.end()) {
    // Kill it with fire.
    if (kill(iter->second.pid(), SIGKILL) != 0) {
      PLOG(ERROR) << "Unable to send SIGKILL to child process";
    }
  }
  // We reap the child process through the normal sigchld handling mechanism.
}

}  // namespace seneschal
}  // namespace vm_tools
