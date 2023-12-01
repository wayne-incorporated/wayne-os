// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sysexits.h>
#include <unistd.h>

#include <map>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/command_line.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/no_destructor.h>
#include <base/numerics/safe_conversions.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/strcat.h>
#include <base/strings/string_piece.h>
#include <brillo/daemons/dbus_daemon.h>
#include <brillo/syslog_logging.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/object_proxy.h>

#include "fusebox/built_in.h"
#include "fusebox/file_system.h"
#include "fusebox/fuse_frontend.h"
#include "fusebox/fuse_path_inodes.h"
#include "fusebox/make_stat.h"
#include "fusebox/proto_bindings/fusebox.pb.h"
#include "fusebox/util.h"

namespace fusebox {

namespace {

void HandleDBusSignalConnected(const std::string& interface,
                               const std::string& signal,
                               bool success) {
  if (!success) {
    LOG(ERROR) << "Failed to connect to D-Bus signal " << interface << "."
               << signal;
  }
}

template <typename ResponseProto>
int ReadDBusProto(dbus::Response* response, ResponseProto* proto) {
  if (!response) {
    return ETIMEDOUT;
  } else if (!dbus::MessageReader(response).PopArrayOfBytesAsProto(proto)) {
    return EPROTO;
  } else if (proto->has_posix_error_code()) {
    return proto->posix_error_code();
  }
  return 0;
}

}  // namespace

class FuseBoxClient : public FileSystem {
 public:
  FuseBoxClient(scoped_refptr<dbus::Bus> bus, FuseMount* fuse)
      : fuse_(fuse), weak_ptr_factory_(this) {}
  FuseBoxClient(const FuseBoxClient&) = delete;
  FuseBoxClient& operator=(const FuseBoxClient&) = delete;
  virtual ~FuseBoxClient() = default;

  void OnDBusDaemonInit(scoped_refptr<dbus::Bus> bus) {
    const auto path = dbus::ObjectPath(kFuseBoxServicePath);
    dbus_proxy_ = bus->GetObjectProxy(kFuseBoxServiceName, path);

    dbus_proxy_->ConnectToSignal(
        kFuseBoxServiceInterface, kStorageAttachedSignal,
        base::BindRepeating(&FuseBoxClient::OnStorageAttached,
                            weak_ptr_factory_.GetWeakPtr()),
        base::BindOnce(&HandleDBusSignalConnected));
    dbus_proxy_->ConnectToSignal(
        kFuseBoxServiceInterface, kStorageDetachedSignal,
        base::BindRepeating(&FuseBoxClient::OnStorageDetached,
                            weak_ptr_factory_.GetWeakPtr()),
        base::BindOnce(&HandleDBusSignalConnected));

    dbus::MethodCall method(kFuseBoxServiceInterface, kListStoragesMethod);
    dbus::MessageWriter writer(&method);
    ListStoragesRequestProto request_proto;
    writer.AppendProtoAsArrayOfBytes(request_proto);
    CallFuseBoxServerMethod(&method,
                            base::BindOnce(&FuseBoxClient::ListStoragesResponse,
                                           weak_ptr_factory_.GetWeakPtr()));
  }

  void ListStoragesResponse(dbus::Response* response) {
    VLOG(1) << "liststorages-resp";

    ListStoragesResponseProto response_proto;
    if (errno = ReadDBusProto(response, &response_proto); errno) {
      PLOG(ERROR) << "liststorages-resp";
      return;
    }
    for (const auto& subdir : response_proto.storages()) {
      DoAttachStorage(subdir, 0);
    }
  }

  int StartFuseSession(base::OnceClosure stop_callback) {
    CHECK(stop_callback);

    fuse_frontend_.reset(new FuseFrontend(fuse_));
    if (!fuse_frontend_->CreateFuseSession(this, FileSystem::FuseOps()))
      return EX_SOFTWARE;

    dbus_proxy_->SetNameOwnerChangedCallback(base::BindRepeating(
        &FuseBoxClient::ServiceOwnerChanged, weak_ptr_factory_.GetWeakPtr()));
    fuse_frontend_->StartFuseSession(std::move(stop_callback));
    return EX_OK;
  }

  void ServiceOwnerChanged(const std::string&, const std::string& owner) {
    if (owner.empty()) {
      PLOG(ERROR) << "service owner changed";
      fuse_frontend_->StopFuseSession(errno);
    }
  }

  static InodeTable& GetInodeTable() {
    static base::NoDestructor<InodeTable> inode_table;
    return *inode_table;
  }

  static AccessMode CreateAccessMode(int flags) {
    switch (flags & O_ACCMODE) {
      case O_RDONLY:
        return AccessMode::READ_ONLY;
      case O_WRONLY:
        return AccessMode::WRITE_ONLY;
      case O_RDWR:
        return AccessMode::READ_WRITE;
    }
    return AccessMode::NO_ACCESS;
  }

  template <typename Signature>
  void CallFuseBoxServerMethod(dbus::MethodCall* method_call,
                               base::OnceCallback<Signature> callback) {
    // Use a relatively long timeout (55 minutes in milliseconds), compared to
    // the default of 25000 milliseconds (25 seconds). Fusebox D-Bus calls can
    // lead to network I/O, possibly to "storage in the cloud". These can take
    // a while to respond.
    constexpr int timeout_ms = 3300000;
    dbus_proxy_->CallMethod(method_call, timeout_ms, std::move(callback));
  }

  void Init(void* userdata, struct fuse_conn_info*) override {
    VLOG(1) << "init";

    Node* root = GetInodeTable().Lookup(FUSE_ROOT_ID);
    struct stat root_stat = MakeTimeStat(S_IFDIR | 0770);
    root_stat = MakeStat(root->ino, root_stat);
    GetInodeTable().SetStat(root->ino, root_stat);

    CHECK_EQ(0, DoAttachStorage("built_in", INO_BUILT_IN));
    BuiltInEnsureNodes(GetInodeTable());

    CHECK(userdata) << "FileSystem (userdata) is required";
  }

  void GetFsattr(std::unique_ptr<FsattrRequest> request) override {
    // Without overriding this GetFsattr method, we'd report "zero bytes free
    // disk space" by default. This would mean that other programs that first
    // check "is there enough space" before copying in files would balk.
    //
    // This Fusebox daemon can serve multiple subdirs, often backed by the
    // cloud instead of by physical storage on Chromebook-local disks. It's
    // non-trivial to get an accurate estimate of "how much free disk space"
    // there is in total under /media/fuse/fusebox.
    //
    // But we don't need accuracy to pass the "is there enough space" check.
    // And even with accuracy, reporting enough space (a big enough number)
    // across *all* subdirs doesn't imply that there was enough space on *one
    // particular* subdir you're copying into.
    //
    // Instead, we'll just make up an arbitrary big number (1099511627776 bytes
    // = 1 tebibyte), enough to effectively always say "go ahead, try to copy".
    // If it turns out that there wasn't enough space, the copy will fail. But
    // copies can already fail, in a "not enough space" way (if something else
    // is concurrently writing to the "disk") and in other ways.
    //
    // See also: "man 2 statfs" and "man 3 statvfs".

    struct statvfs stat = {0};
    stat.f_bsize = 4096;      // The block size is 1<<12.
    stat.f_frsize = 4096;     // On Linux, fragment size = block size.
    stat.f_blocks = 1 << 28;  // There are 1<<28 blocks, all free (unused) and
    stat.f_bfree = 1 << 28;   // available (for unprivileged users), and so
    stat.f_bavail = 1 << 28;  // there is 1<<40 = 1TiB of "free disk space".
    stat.f_files = 1 << 20;   // There are also over 1 million free inodes.
    stat.f_ffree = 1 << 20;
    stat.f_favail = 1 << 20;
    stat.f_fsid = 0;
    stat.f_flag = ST_NODEV | ST_NOEXEC | ST_NOSUID;
    stat.f_namemax = NAME_MAX;
    request->ReplyFsattr(stat);
  }

  void GetAttr(std::unique_ptr<AttrRequest> request, ino_t ino) override {
    VLOG(1) << "getattr " << ino;

    if (request->IsInterrupted())
      return;

    Node* node = GetInodeTable().Lookup(ino);
    if (!node) {
      request->ReplyError(errno);
      PLOG(ERROR) << "getattr";
      return;
    }

    if (node->parent <= FUSE_ROOT_ID) {
      struct stat stat;
      CHECK(GetInodeTable().GetStat(node->ino, &stat));
      request->ReplyAttr(stat, kStatTimeoutSeconds);
      return;
    } else if (node->parent == INO_BUILT_IN) {
      struct stat stat;
      BuiltInGetStat(node->ino, &stat);
      request->ReplyAttr(stat, kStatTimeoutSeconds);
      return;
    }

    Stat2RequestProto request_proto;
    request_proto.set_file_system_url(GetInodeTable().GetDevicePath(node));

    dbus::MethodCall method(kFuseBoxServiceInterface, kStat2Method);
    dbus::MessageWriter writer(&method);
    writer.AppendProtoAsArrayOfBytes(request_proto);

    auto stat_response = base::BindOnce(&FuseBoxClient::StatResponse,
                                        weak_ptr_factory_.GetWeakPtr(),
                                        std::move(request), node->ino);
    CallFuseBoxServerMethod(&method, std::move(stat_response));
  }

  void StatResponse(std::unique_ptr<AttrRequest> request,
                    ino_t ino,
                    dbus::Response* response) {
    VLOG(1) << "getattr-resp " << ino;

    if (request->IsInterrupted()) {
      return;
    }
    Stat2ResponseProto response_proto;
    if (errno = ReadDBusProto(response, &response_proto); errno) {
      request->ReplyError(errno);
      PLOG(ERROR) << "getattr-resp";
      return;
    } else if (!response_proto.has_stat()) {
      request->ReplyError(EINVAL);
      return;
    }

    request->ReplyAttr(MakeStatFromProto(ino, response_proto.stat()),
                       kStatTimeoutSeconds);
  }

  void Lookup(std::unique_ptr<EntryRequest> request,
              ino_t parent,
              const char* name) override {
    VLOG(1) << "lookup " << parent << "/" << name;

    if (request->IsInterrupted())
      return;

    if (parent <= FUSE_ROOT_ID) {
      RootLookup(std::move(request), name);
      return;
    } else if (parent == INO_BUILT_IN) {
      BuiltInLookup(std::move(request), name);
      return;
    }

    Node* parent_node = GetInodeTable().Lookup(parent);
    if (!parent_node) {
      request->ReplyError(errno);
      PLOG(ERROR) << "lookup parent";
      return;
    }

    Stat2RequestProto request_proto;
    request_proto.set_file_system_url(
        base::StrCat({GetInodeTable().GetDevicePath(parent_node), "/", name}));

    dbus::MethodCall method(kFuseBoxServiceInterface, kStat2Method);
    dbus::MessageWriter writer(&method);
    writer.AppendProtoAsArrayOfBytes(request_proto);

    auto lookup_response = base::BindOnce(
        &FuseBoxClient::LookupResponse, weak_ptr_factory_.GetWeakPtr(),
        std::move(request), parent, std::string(name));
    CallFuseBoxServerMethod(&method, std::move(lookup_response));
  }

  void RootLookup(std::unique_ptr<EntryRequest> request, std::string name) {
    VLOG(1) << "root-lookup" << FUSE_ROOT_ID << "/" << name;

    // Look for a device directory that we were previously told about (by
    // DoAttachStorage, typically via the OnStorageAttached D-Bus signal).
    auto it = device_dir_entry_.find(name);
    if (it != device_dir_entry_.end()) {
      DoRootLookup(std::move(request), it->second.ino);
      return;
    }

    // If we didn't find one, it's probably ENOENT, but there's also the
    // unlikely possibility that there was a race (since Chrome and FuseBox are
    // separate processes and D-Bus IPC can also bounce through the kernel)
    // where we get the FUSE request before the corresponding OnStorageAttached
    // D-Bus signal. We therefore ask the Chrome process (via a D-Bus method
    // call) whether the subdir exists (and reply ENOENT if it doesn't).

    Stat2RequestProto request_proto;
    request_proto.set_file_system_url(name);

    dbus::MethodCall method(kFuseBoxServiceInterface, kStat2Method);
    dbus::MessageWriter writer(&method);
    writer.AppendProtoAsArrayOfBytes(request_proto);

    auto stat_response = base::BindOnce(&FuseBoxClient::RootLookupResponse,
                                        weak_ptr_factory_.GetWeakPtr(),
                                        std::move(request), name);
    CallFuseBoxServerMethod(&method, std::move(stat_response));
  }

  void RootLookupResponse(std::unique_ptr<EntryRequest> request,
                          std::string name,
                          dbus::Response* response) {
    VLOG(1) << "rootlookup-resp " << name;

    if (request->IsInterrupted()) {
      return;
    }
    Stat2ResponseProto response_proto;
    if (errno = ReadDBusProto(response, &response_proto); errno) {
      request->ReplyError(errno);
      PLOG(ERROR) << "rootlookup-resp";
      return;
    }

    DoAttachStorage(name, 0);

    auto it = device_dir_entry_.find(name);
    if (it != device_dir_entry_.end()) {
      DoRootLookup(std::move(request), it->second.ino);
      return;
    }
    errno = request->ReplyError(ENOENT);
    PLOG(ERROR) << "rootlookup";
  }

  void DoRootLookup(std::unique_ptr<EntryRequest> request, ino_t ino) {
    fuse_entry_param entry = {0};
    entry.ino = static_cast<fuse_ino_t>(ino);
    CHECK(GetInodeTable().GetStat(ino, &entry.attr));
    entry.attr_timeout = kStatTimeoutSeconds;
    entry.entry_timeout = kEntryTimeoutSeconds;

    request->ReplyEntry(entry);
  }

  void LookupResponse(std::unique_ptr<EntryRequest> request,
                      ino_t parent,
                      std::string name,
                      dbus::Response* response) {
    VLOG(1) << "lookup-resp " << parent << "/" << name;

    if (request->IsInterrupted()) {
      return;
    }
    MkDirResponseProto response_proto;
    if (errno = ReadDBusProto(response, &response_proto); errno) {
      request->ReplyError(errno);
      PLOG(ERROR) << "lookup-resp";
      return;
    }

    Node* node = GetInodeTable().Ensure(parent, name.c_str());
    if (!node) {
      request->ReplyError(errno);
      PLOG(ERROR) << "lookup-resp";
      return;
    }

    fuse_entry_param entry = {0};
    entry.ino = static_cast<fuse_ino_t>(node->ino);
    if (response_proto.has_stat()) {
      entry.attr = MakeStatFromProto(node->ino, response_proto.stat());
    }
    entry.attr_timeout = kEntryTimeoutSeconds;
    entry.entry_timeout = kEntryTimeoutSeconds;

    request->ReplyEntry(entry);
  }

  void SetAttr(std::unique_ptr<AttrRequest> request,
               ino_t ino,
               struct stat* attr,
               int to_set) override {
    VLOG(1) << "SetAttr ino " << ino << " fh " << request->fh();

    if (request->IsInterrupted())
      return;

    Node* node = GetInodeTable().Lookup(ino);
    if (!node) {
      request->ReplyError(errno);
      PLOG(ERROR) << "setattr";
      return;
    } else if (node->ino < FIRST_UNRESERVED_INO) {
      errno = request->ReplyError(errno ? errno : EACCES);
      PLOG(ERROR) << "setattr";
      return;
    }

    // Allow setting file size truncate(2) to support file write(2).
    const int kAllowedToSet = FUSE_SET_ATTR_SIZE;

    constexpr auto allowed_to_set = [](int to_set) {
      if (to_set & ~kAllowedToSet)
        return ENOTSUP;
      if (!to_set)  // Nothing to_set? error EINVAL.
        return EINVAL;
      return 0;
    };

    VLOG(1) << "to_set " << ToSetFlagsToString(to_set);
    if (errno = allowed_to_set(to_set); errno) {
      request->ReplyError(errno);
      PLOG(ERROR) << "setattr";
      return;
    }

    TruncateRequestProto request_proto;
    request_proto.set_file_system_url(GetInodeTable().GetDevicePath(node));
    request_proto.set_length(base::strict_cast<int64_t>(attr->st_size));

    dbus::MethodCall method(kFuseBoxServiceInterface, kTruncateMethod);
    dbus::MessageWriter writer(&method);
    writer.AppendProtoAsArrayOfBytes(request_proto);

    auto truncate_response =
        base::BindOnce(&FuseBoxClient::TruncateResponse,
                       weak_ptr_factory_.GetWeakPtr(), std::move(request), ino);
    CallFuseBoxServerMethod(&method, std::move(truncate_response));
  }

  void TruncateResponse(std::unique_ptr<AttrRequest> request,
                        ino_t ino,
                        dbus::Response* response) {
    VLOG(1) << "truncate-resp " << ino;

    if (request->IsInterrupted()) {
      return;
    }
    TruncateResponseProto response_proto;
    if (errno = ReadDBusProto(response, &response_proto); errno) {
      request->ReplyError(errno);
      PLOG(ERROR) << "truncate-resp";
      return;
    } else if (!response_proto.has_stat()) {
      request->ReplyError(EINVAL);
      return;
    }

    request->ReplyAttr(MakeStatFromProto(ino, response_proto.stat()),
                       kStatTimeoutSeconds);
  }

  void Unlink(std::unique_ptr<OkRequest> request,
              ino_t parent,
              const char* name) override {
    VLOG(1) << "unlink " << parent << "/" << name;

    if (request->IsInterrupted())
      return;

    errno = 0;
    Node* parent_node = GetInodeTable().Lookup(parent);
    if (!parent_node || (parent < FIRST_UNRESERVED_INO)) {
      errno = request->ReplyError(errno ? errno : EACCES);
      PLOG(ERROR) << "unlink";
      return;
    }

    Node* node = GetInodeTable().Lookup(parent, name);
    ino_t ino = node ? node->ino : 0;

    UnlinkRequestProto request_proto;
    request_proto.set_file_system_url(
        base::StrCat({GetInodeTable().GetDevicePath(parent_node), "/", name}));

    dbus::MethodCall method(kFuseBoxServiceInterface, kUnlinkMethod);
    dbus::MessageWriter writer(&method);
    writer.AppendProtoAsArrayOfBytes(request_proto);

    auto unlink_response =
        base::BindOnce(&FuseBoxClient::UnlinkResponse,
                       weak_ptr_factory_.GetWeakPtr(), std::move(request), ino);
    CallFuseBoxServerMethod(&method, std::move(unlink_response));
  }

  void UnlinkResponse(std::unique_ptr<OkRequest> request,
                      ino_t ino,
                      dbus::Response* response) {
    VLOG(1) << "unlink-resp " << ino;

    if (request->IsInterrupted()) {
      return;
    }
    UnlinkResponseProto response_proto;
    if (errno = ReadDBusProto(response, &response_proto); errno) {
      request->ReplyError(errno);
      PLOG(ERROR) << "unlink-resp";
      return;
    }

    if (ino) {
      GetInodeTable().Forget(ino);
    }
    request->ReplyOk();
  }

  void OpenDir(std::unique_ptr<OpenRequest> request, ino_t ino) override {
    VLOG(1) << "opendir " << ino;

    if (request->IsInterrupted())
      return;

    if ((request->flags() & O_ACCMODE) != O_RDONLY) {
      errno = request->ReplyError(EACCES);
      PLOG(ERROR) << "opendir";
      return;
    }

    Node* node = GetInodeTable().Lookup(ino);
    if (!node) {
      request->ReplyError(errno);
      PLOG(ERROR) << "opendir";
      return;
    }

    uint64_t client_side_fuse_handle = NextClientSideFuseHandle();
    if (ino >= FIRST_UNRESERVED_INO) {
      dir_entry_buffers_.insert(std::pair{client_side_fuse_handle,
                                          std::make_unique<DirEntryBuffer>()});
      CallReadDir2(ino, GetInodeTable().GetDevicePath(node), 0, 0,
                   client_side_fuse_handle);
    }
    request->ReplyOpen(client_side_fuse_handle);
  }

  void ReadDir(std::unique_ptr<DirEntryRequest> request,
               ino_t ino,
               off_t off) override {
    VLOG(1) << "readdir fh " << request->fh() << " off " << off;

    if (request->IsInterrupted())
      return;

    Node* node = GetInodeTable().Lookup(ino);
    if (!node) {
      request->ReplyError(errno);
      PLOG(ERROR) << "readdir";
      return;
    } else if (node->ino <= FUSE_ROOT_ID) {
      RootReadDir(off, std::move(request));
      return;
    } else if (node->ino == INO_BUILT_IN) {
      BuiltInReadDir(off, std::move(request));
      return;
    }

    uint64_t fuse_handle = request->fh();
    auto it = dir_entry_buffers_.find(fuse_handle);
    if (it == dir_entry_buffers_.end()) {
      errno = request->ReplyError(EINVAL);
      PLOG(ERROR) << "readdir";
      return;
    }
    it->second->AppendRequest(std::move(request));
  }

  void RootReadDir(off_t off, std::unique_ptr<DirEntryRequest> request) {
    VLOG(1) << "root-readdir off " << off;

    size_t i = 0;
    for (const auto& item : device_dir_entry_) {
      if (i < off) {
        // No-op.
      } else if (!request->AddEntry(item.second, i + 1)) {
        break;
      }
      i++;
    }
    request->ReplyDone();
  }

  void CallReadDir2(ino_t parent_ino,
                    std::string parent_path,
                    uint64_t cookie,
                    int32_t cancel_error_code,
                    uint64_t client_side_fuse_handle) {
    ReadDir2RequestProto request_proto;
    request_proto.set_file_system_url(parent_path);
    request_proto.set_cookie(cookie);
    request_proto.set_cancel_error_code(cancel_error_code);

    dbus::MethodCall method(kFuseBoxServiceInterface, kReadDir2Method);
    dbus::MessageWriter writer(&method);
    writer.AppendProtoAsArrayOfBytes(request_proto);

    auto readdir2_response = base::BindOnce(
        &FuseBoxClient::ReadDir2Response, weak_ptr_factory_.GetWeakPtr(),
        parent_path, parent_ino, client_side_fuse_handle);
    CallFuseBoxServerMethod(&method, std::move(readdir2_response));
  }

  void ReadDir2Response(std::string parent_path,
                        ino_t parent_ino,
                        uint64_t client_side_fuse_handle,
                        dbus::Response* response) {
    VLOG(1) << "readdir2-resp";

    DirEntryBuffer* dir_entry_buffer = nullptr;
    if (auto it = dir_entry_buffers_.find(client_side_fuse_handle);
        it != dir_entry_buffers_.end()) {
      dir_entry_buffer = it->second.get();
    }

    ReadDir2ResponseProto response_proto;
    if (errno = ReadDBusProto(response, &response_proto); errno) {
      if (dir_entry_buffer) {
        dir_entry_buffer->AppendResponse(errno);
      }
      PLOG(ERROR) << "readdir2-resp";
      return;
    }
    uint64_t cookie = response_proto.has_cookie() ? response_proto.cookie() : 0;

    if (!dir_entry_buffer) {
      if (cookie != 0) {
        // Per the fusebox.proto comments, a non-zero cookie (in a D-Bus RPC
        // response) means that the D-Bus server is expecting a follow-up D-Bus
        // RPC request, even if the downstream FUSE request is invalid (i.e.
        // even if dir_entry_buffer is nullptr).
        CallReadDir2(parent_ino, std::move(parent_path), cookie, EINVAL,
                     client_side_fuse_handle);
      }
      return;
    }

    std::vector<fusebox::DirEntry> entries;
    for (const auto& item : response_proto.entries()) {
      const char* name = item.name().c_str();
      if (Node* node = GetInodeTable().Ensure(parent_ino, name)) {
        entries.push_back(
            {node->ino, item.name(), MakeStatModeBits(item.mode_bits())});
      } else {
        dir_entry_buffer->AppendResponse(errno);
        PLOG(ERROR) << "readdir2-resp";
        if (cookie != 0) {
          // Per the fusebox.proto comments, as above, a non-zero cookie means
          // that we still need to send another D-Bus request. The non-zero
          // cancel_error_code = errno argument tells the D-Bus server to
          // cancel the overall operation, but it still needs explicitly being
          // told that.
          CallReadDir2(parent_ino, std::move(parent_path), cookie, errno,
                       client_side_fuse_handle);
        }
        return;
      }
    }
    dir_entry_buffer->AppendResponse(std::move(entries), cookie == 0);

    if (cookie != 0) {
      CallReadDir2(parent_ino, std::move(parent_path), cookie, 0,
                   client_side_fuse_handle);
    }
  }

  void ReleaseDir(std::unique_ptr<OkRequest> request, ino_t ino) override {
    VLOG(1) << "releasedir fh " << request->fh();

    if (request->IsInterrupted())
      return;

    dir_entry_buffers_.erase(request->fh());
    request->ReplyOk();
  }

  void MkDir(std::unique_ptr<EntryRequest> request,
             ino_t parent,
             const char* name,
             mode_t mode) override {
    VLOG(1) << "mkdir " << parent << "/" << name;

    if (request->IsInterrupted())
      return;

    errno = 0;
    Node* parent_node = GetInodeTable().Lookup(parent);
    if (!parent_node || (parent < FIRST_UNRESERVED_INO)) {
      errno = request->ReplyError(errno ? errno : EACCES);
      PLOG(ERROR) << "mkdir";
      return;
    }

    Node* node = GetInodeTable().Create(parent, name);
    if (!node) {
      request->ReplyError(errno);
      PLOG(ERROR) << "mkdir child";
      return;
    }

    MkDirRequestProto request_proto;
    request_proto.set_file_system_url(GetInodeTable().GetDevicePath(node));

    dbus::MethodCall method(kFuseBoxServiceInterface, kMkDirMethod);
    dbus::MessageWriter writer(&method);
    writer.AppendProtoAsArrayOfBytes(request_proto);

    auto mkdir_response = base::BindOnce(&FuseBoxClient::MkDirResponse,
                                         weak_ptr_factory_.GetWeakPtr(),
                                         std::move(request), node->ino);
    CallFuseBoxServerMethod(&method, std::move(mkdir_response));
  }

  void MkDirResponse(std::unique_ptr<EntryRequest> request,
                     ino_t ino,
                     dbus::Response* response) {
    VLOG(1) << "mkdir-resp " << ino;

    if (request->IsInterrupted()) {
      GetInodeTable().Forget(ino);
      return;
    }
    MkDirResponseProto response_proto;
    if (errno = ReadDBusProto(response, &response_proto); errno) {
      GetInodeTable().Forget(ino);
      request->ReplyError(errno);
      PLOG(ERROR) << "mkdir-resp";
      return;
    }

    fuse_entry_param entry = {0};
    entry.ino = static_cast<fuse_ino_t>(ino);
    if (response_proto.has_stat()) {
      entry.attr = MakeStatFromProto(ino, response_proto.stat());
    }
    entry.attr_timeout = kEntryTimeoutSeconds;
    entry.entry_timeout = kEntryTimeoutSeconds;

    request->ReplyEntry(entry);
  }

  void RmDir(std::unique_ptr<OkRequest> request,
             ino_t parent,
             const char* name) override {
    VLOG(1) << "rmdir " << parent << "/" << name;

    if (request->IsInterrupted())
      return;

    errno = 0;
    Node* parent_node = GetInodeTable().Lookup(parent);
    if (!parent_node || (parent < FIRST_UNRESERVED_INO)) {
      errno = request->ReplyError(errno ? errno : EACCES);
      PLOG(ERROR) << "rmdir";
      return;
    }

    Node* node = GetInodeTable().Lookup(parent, name);
    ino_t ino = node ? node->ino : 0;

    RmDirRequestProto request_proto;
    request_proto.set_file_system_url(
        base::StrCat({GetInodeTable().GetDevicePath(parent_node), "/", name}));

    dbus::MethodCall method(kFuseBoxServiceInterface, kRmDirMethod);
    dbus::MessageWriter writer(&method);
    writer.AppendProtoAsArrayOfBytes(request_proto);

    auto rmdir_response =
        base::BindOnce(&FuseBoxClient::RmDirResponse,
                       weak_ptr_factory_.GetWeakPtr(), std::move(request), ino);
    CallFuseBoxServerMethod(&method, std::move(rmdir_response));
  }

  void RmDirResponse(std::unique_ptr<OkRequest> request,
                     ino_t ino,
                     dbus::Response* response) {
    VLOG(1) << "rmdir-resp " << ino;

    if (request->IsInterrupted()) {
      return;
    }
    RmDirResponseProto response_proto;
    if (errno = ReadDBusProto(response, &response_proto); errno) {
      request->ReplyError(errno);
      PLOG(ERROR) << "rmdir-resp";
      return;
    }

    if (ino) {
      GetInodeTable().Forget(ino);
    }
    request->ReplyOk();
  }

  void Rename(std::unique_ptr<OkRequest> request,
              ino_t old_parent,
              const char* old_name,
              ino_t new_parent,
              const char* new_name) override {
    VLOG(1) << "rename " << old_parent << "/" << old_name << " " << new_parent
            << "/" << new_name;

    if (request->IsInterrupted())
      return;

    errno = 0;
    Node* old_parent_node = GetInodeTable().Lookup(old_parent);
    Node* new_parent_node = GetInodeTable().Lookup(new_parent);
    if (!old_parent_node || (old_parent < FIRST_UNRESERVED_INO) ||
        !new_parent_node || (new_parent < FIRST_UNRESERVED_INO)) {
      errno = request->ReplyError(errno ? errno : EACCES);
      PLOG(ERROR) << "rename";
      return;
    }

    RenameRequestProto request_proto;
    request_proto.set_src_file_system_url(base::StrCat(
        {GetInodeTable().GetDevicePath(old_parent_node), "/", old_name}));
    request_proto.set_dst_file_system_url(base::StrCat(
        {GetInodeTable().GetDevicePath(new_parent_node), "/", new_name}));

    dbus::MethodCall method(kFuseBoxServiceInterface, kRenameMethod);
    dbus::MessageWriter writer(&method);
    writer.AppendProtoAsArrayOfBytes(request_proto);

    auto rename_response = base::BindOnce(
        &FuseBoxClient::RenameResponse, weak_ptr_factory_.GetWeakPtr(),
        std::move(request), old_parent, std::string(old_name), new_parent,
        std::string(new_name));
    CallFuseBoxServerMethod(&method, std::move(rename_response));
  }

  void RenameResponse(std::unique_ptr<OkRequest> request,
                      ino_t old_parent,
                      std::string old_name,
                      ino_t new_parent,
                      std::string new_name,
                      dbus::Response* response) {
    VLOG(1) << "rename-resp";

    if (request->IsInterrupted()) {
      return;
    }
    RenameResponseProto response_proto;
    if (errno = ReadDBusProto(response, &response_proto); errno) {
      request->ReplyError(errno);
      PLOG(ERROR) << "rename-resp";
      return;
    }

    Node* node = GetInodeTable().Lookup(old_parent, old_name.c_str());
    if (node) {
      GetInodeTable().Move(node, new_parent, new_name.c_str());
    }

    request->ReplyOk();
  }

  void Open(std::unique_ptr<OpenRequest> request, ino_t ino) override {
    VLOG(1) << "open " << ino;

    if (request->IsInterrupted())
      return;

    Node* node = GetInodeTable().Lookup(ino);
    if (!node) {
      request->ReplyError(errno);
      PLOG(ERROR) << "open";
      return;
    } else if (node->parent <= FUSE_ROOT_ID) {
      errno = request->ReplyError(errno ? errno : EACCES);
      PLOG(ERROR) << "open";
      return;
    } else if (node->parent == INO_BUILT_IN) {
      if ((request->flags() & O_ACCMODE) != O_RDONLY) {
        errno = request->ReplyError(EACCES);
        PLOG(ERROR) << "open";
        return;
      }
      request->ReplyOpen(NextClientSideFuseHandle());
      return;
    }

    Open2RequestProto request_proto;
    request_proto.set_file_system_url(GetInodeTable().GetDevicePath(node));
    request_proto.set_access_mode(CreateAccessMode(request->flags()));

    dbus::MethodCall method(kFuseBoxServiceInterface, kOpen2Method);
    dbus::MessageWriter writer(&method);
    writer.AppendProtoAsArrayOfBytes(request_proto);

    auto open2_response =
        base::BindOnce(&FuseBoxClient::Open2Response,
                       weak_ptr_factory_.GetWeakPtr(), std::move(request), ino);
    CallFuseBoxServerMethod(&method, std::move(open2_response));
  }

  void Open2Response(std::unique_ptr<OpenRequest> request,
                     ino_t ino,
                     dbus::Response* response) {
    VLOG(1) << "open2-resp";

    if (request->IsInterrupted()) {
      return;
    }
    Open2ResponseProto response_proto;
    if (errno = ReadDBusProto(response, &response_proto); errno) {
      request->ReplyError(errno);
      PLOG(ERROR) << "open2-resp";
      return;
    }
    uint64_t server_side_fuse_handle =
        response_proto.has_fuse_handle() ? response_proto.fuse_handle() : 0;

    request->ReplyOpen(server_side_fuse_handle);
  }

  void Read(std::unique_ptr<BufferRequest> request,
            ino_t ino,
            size_t size,
            off_t off) override {
    VLOG(1) << "read fh " << request->fh() << " off " << off << " size "
            << size;

    if (request->IsInterrupted())
      return;

    if (size > SSIZE_MAX) {
      errno = request->ReplyError(EINVAL);
      PLOG(ERROR) << "read";
      return;
    }

    if (ino < FIRST_UNRESERVED_INO) {
      BuiltInRead(dbus_proxy_, std::move(request), ino, size, off);
      return;
    }

    uint64_t fuse_handle = request->fh();
    if (fuse_handle == 0) {
      errno = request->ReplyError(EBADF);
      PLOG(ERROR) << "read";
      return;
    }

    CallRead2(std::move(request), fuse_handle, size, off, std::vector<char>());
  }

  void CallRead2(std::unique_ptr<BufferRequest> request,
                 uint64_t fuse_handle,
                 size_t size,
                 off_t off,
                 std::vector<char> previous_data) {
    Read2RequestProto request_proto;
    request_proto.set_fuse_handle(fuse_handle);
    request_proto.set_offset(off);
    request_proto.set_length(size);

    dbus::MethodCall method(kFuseBoxServiceInterface, kRead2Method);
    dbus::MessageWriter writer(&method);
    writer.AppendProtoAsArrayOfBytes(request_proto);

    auto read2_response = base::BindOnce(
        &FuseBoxClient::Read2Response, weak_ptr_factory_.GetWeakPtr(),
        std::move(request), fuse_handle, size, off, std::move(previous_data));
    CallFuseBoxServerMethod(&method, std::move(read2_response));
  }

  void Read2Response(std::unique_ptr<BufferRequest> request,
                     uint64_t fuse_handle,
                     size_t size,
                     off_t off,
                     std::vector<char> previous_data,
                     dbus::Response* response) {
    VLOG(1) << "read2-resp";

    if (request->IsInterrupted()) {
      return;
    }
    Read2ResponseProto response_proto;
    if (errno = ReadDBusProto(response, &response_proto); errno) {
      request->ReplyError(errno);
      PLOG(ERROR) << "read2-resp";
      return;
    }

    const std::string& data = response_proto.data();
    const char* data_ptr = data.data();
    const size_t data_len = data.size();

    // Both the FUSE API and Chrome's storage C++ API have a "read up to MAX
    // bytes" method. The semantics are subtly different when returning "N
    // bytes were read". (N == 0) means EOF-or-error in both cases. (0 < N) &&
    // (N < MAX) always means EOF-or-error for FUSE but not necessarily so for
    // Chrome. In that case, save the partial response in the previous_data
    // vector and issue another Chrome read call (via D-Bus).
    bool partial_response = (0 < data_len) && (data_len < size);

    if (!partial_response && previous_data.empty()) {
      request->ReplyBuffer(data_ptr, data_len);
      return;
    }
    previous_data.reserve(size);
    previous_data.insert(previous_data.end(), data_ptr, data_ptr + data_len);
    if (!partial_response) {
      request->ReplyBuffer(previous_data.data(), previous_data.size());
      return;
    } else if ((off_t)(off + data_len) < off) {
      errno = EINVAL;
      request->ReplyError(errno);
      PLOG(ERROR) << "read2-resp";
      return;
    }
    size -= data_len;
    off += data_len;
    CallRead2(std::move(request), fuse_handle, size, off,
              std::move(previous_data));
  }

  void Write(std::unique_ptr<WriteRequest> request,
             ino_t ino,
             const char* buf,
             size_t size,
             off_t off) override {
    VLOG(1) << "write ino " << ino << " off " << off << " size " << size;

    if (request->IsInterrupted())
      return;

    if (size > SSIZE_MAX) {
      errno = request->ReplyError(EINVAL);
      PLOG(ERROR) << "write";
      return;
    }

    if (ino < FIRST_UNRESERVED_INO) {
      errno = request->ReplyError(errno ? errno : EACCES);
      PLOG(ERROR) << "write";
      return;
    }

    uint64_t fuse_handle = request->fh();
    if (fuse_handle == 0) {
      errno = request->ReplyError(EBADF);
      PLOG(ERROR) << "write";
      return;
    }

    Write2RequestProto request_proto;
    request_proto.set_fuse_handle(fuse_handle);
    request_proto.set_offset(off);
    request_proto.mutable_data()->append(buf, size);

    dbus::MethodCall method(kFuseBoxServiceInterface, kWrite2Method);
    dbus::MessageWriter writer(&method);
    writer.AppendProtoAsArrayOfBytes(request_proto);

    auto write2_response = base::BindOnce(&FuseBoxClient::Write2Response,
                                          weak_ptr_factory_.GetWeakPtr(),
                                          std::move(request), size);
    CallFuseBoxServerMethod(&method, std::move(write2_response));
  }

  void Write2Response(std::unique_ptr<WriteRequest> request,
                      size_t length,
                      dbus::Response* response) {
    VLOG(1) << "write2-resp";

    if (request->IsInterrupted()) {
      return;
    }
    Write2ResponseProto response_proto;
    if (errno = ReadDBusProto(response, &response_proto); errno) {
      request->ReplyError(errno);
      PLOG(ERROR) << "write2-resp";
      return;
    }

    request->ReplyWrite(length);
  }

  void Release(std::unique_ptr<OkRequest> request, ino_t ino) override {
    VLOG(1) << "release fh " << request->fh();

    if (request->IsInterrupted())
      return;

    uint64_t fuse_handle = request->fh();
    if (fuse_handle == 0) {
      errno = request->ReplyError(EBADF);
      PLOG(ERROR) << "release";
      return;
    } else if (IsClientSideFuseHandle(fuse_handle)) {
      request->ReplyOk();
      return;
    }

    Close2RequestProto request_proto;
    request_proto.set_fuse_handle(fuse_handle);

    dbus::MethodCall method(kFuseBoxServiceInterface, kClose2Method);
    dbus::MessageWriter writer(&method);
    writer.AppendProtoAsArrayOfBytes(request_proto);

    auto close2_response =
        base::BindOnce(&FuseBoxClient::Close2Response,
                       weak_ptr_factory_.GetWeakPtr(), std::move(request));
    CallFuseBoxServerMethod(&method, std::move(close2_response));
  }

  void Close2Response(std::unique_ptr<OkRequest> request,
                      dbus::Response* response) {
    VLOG(1) << "close2-resp fh " << request->fh();

    if (request->IsInterrupted()) {
      return;
    }
    Close2ResponseProto response_proto;
    if (errno = ReadDBusProto(response, &response_proto); errno) {
      request->ReplyError(errno);
      PLOG(ERROR) << "close2-resp";
      return;
    }

    request->ReplyOk();
  }

  void Create(std::unique_ptr<CreateRequest> request,
              ino_t parent,
              const char* name,
              mode_t mode) override {
    VLOG(1) << "create " << parent << "/" << name;

    if (request->IsInterrupted())
      return;

    errno = 0;
    if (!S_ISREG(mode)) {
      errno = request->ReplyError(ENOTSUP);
      PLOG(ERROR) << "create: regular file expected";
      return;
    }

    Node* parent_node = GetInodeTable().Lookup(parent);
    if (!parent_node || parent < FIRST_UNRESERVED_INO) {
      errno = request->ReplyError(errno ? errno : EACCES);
      PLOG(ERROR) << "create";
      return;
    }

    Node* node = GetInodeTable().Create(parent, name);
    if (!node) {
      request->ReplyError(errno);
      PLOG(ERROR) << "create child";
      return;
    }

    CreateRequestProto request_proto;
    request_proto.set_file_system_url(GetInodeTable().GetDevicePath(node));

    dbus::MethodCall method(kFuseBoxServiceInterface, kCreateMethod);
    dbus::MessageWriter writer(&method);
    writer.AppendProtoAsArrayOfBytes(request_proto);

    auto create_response = base::BindOnce(&FuseBoxClient::CreateResponse,
                                          weak_ptr_factory_.GetWeakPtr(),
                                          std::move(request), node->ino);
    CallFuseBoxServerMethod(&method, std::move(create_response));
  }

  void CreateResponse(std::unique_ptr<CreateRequest> request,
                      ino_t ino,
                      dbus::Response* response) {
    VLOG(1) << "create-resp " << ino;

    if (request->IsInterrupted()) {
      GetInodeTable().Forget(ino);
      return;
    }
    CreateResponseProto response_proto;
    if (errno = ReadDBusProto(response, &response_proto); errno) {
      GetInodeTable().Forget(ino);
      request->ReplyError(errno);
      PLOG(ERROR) << "create-resp";
      return;
    }

    fuse_entry_param entry = {0};
    entry.ino = static_cast<fuse_ino_t>(ino);
    if (response_proto.has_stat()) {
      entry.attr = MakeStatFromProto(ino, response_proto.stat());
    }
    entry.attr_timeout = kEntryTimeoutSeconds;
    entry.entry_timeout = kEntryTimeoutSeconds;

    request->SetEntry(entry);

    uint64_t server_side_fuse_handle =
        response_proto.has_fuse_handle() ? response_proto.fuse_handle() : 0;

    request->ReplyOpen(server_side_fuse_handle);
  }

  void OnStorageAttached(dbus::Signal* signal) {
    dbus::MessageReader reader(signal);
    std::string subdir;
    if (!reader.PopString(&subdir)) {
      return;
    }
    DoAttachStorage(subdir, 0);
  }

  int32_t DoAttachStorage(const std::string& name, ino_t ino) {
    VLOG(1) << "attach-storage " << name;

    Device device = GetInodeTable().MakeFromName(name);
    Node* node = GetInodeTable().AttachDevice(FUSE_ROOT_ID, device, ino);
    if (!node)
      return errno;

    struct stat stat = MakeTimeStat(S_IFDIR | 0770);
    stat = MakeStat(node->ino, stat, device.mode == "ro");
    device_dir_entry_[device.name] = {node->ino, device.name, stat.st_mode};
    GetInodeTable().SetStat(node->ino, stat);
    return 0;
  }

  void OnStorageDetached(dbus::Signal* signal) {
    dbus::MessageReader reader(signal);
    std::string subdir;
    if (!reader.PopString(&subdir)) {
      return;
    }

    VLOG(1) << "detach-storage " << subdir;

    auto it = device_dir_entry_.find(subdir);
    if (it == device_dir_entry_.end())
      return;
    GetInodeTable().DetachDevice(it->second.ino);
    device_dir_entry_.erase(it);
  }

 private:
  static uint64_t NextClientSideFuseHandle() {
    // As the fusebox.proto comment says, "The high bit (also known as the
    // 1<<63 bit) is also always zero for valid [Fusebox server generated]
    // values, so that the Fusebox client (which is itself a FUSE server) can
    // re-purpose large uint64 values (e.g. for tracking FUSE requests that do
    // not need a round-trip to the Fusebox server)".
    static uint64_t next_fuse_handle = 0x8000'0000'0000'0000ul;
    uint64_t fuse_handle = next_fuse_handle++;
    DCHECK_EQ(fuse_handle >> 63, 1);
    return fuse_handle;
  }

  static bool IsClientSideFuseHandle(uint64_t fuse_handle) {
    return (fuse_handle >> 63) == 1;
  }

  // Server D-Bus proxy.
  scoped_refptr<dbus::ObjectProxy> dbus_proxy_;

  // Map device name to device DirEntry.
  std::map<std::string, DirEntry> device_dir_entry_;

  // Fuse mount: not owned.
  FuseMount* fuse_ = nullptr;

  // Fuse user-space frontend.
  std::unique_ptr<FuseFrontend> fuse_frontend_;

  // ReadDir buffers, keyed by the client-side FUSE handle.
  std::map<uint64_t, std::unique_ptr<DirEntryBuffer>> dir_entry_buffers_;

  base::WeakPtrFactory<FuseBoxClient> weak_ptr_factory_;
};

class FuseBoxDaemon : public brillo::DBusDaemon {
 public:
  explicit FuseBoxDaemon(FuseMount* fuse)
      : fuse_(fuse), weak_ptr_factory_(this) {}
  FuseBoxDaemon(const FuseBoxDaemon&) = delete;
  FuseBoxDaemon& operator=(const FuseBoxDaemon&) = delete;
  ~FuseBoxDaemon() = default;

 protected:
  // brillo::DBusDaemon overrides.

  int OnInit() override {
    int ret = DBusDaemon::OnInit();
    if (ret != EX_OK)
      return ret;

    bus_->AssertOnDBusThread();

    client_ = std::make_unique<FuseBoxClient>(bus_, fuse_);
    client_->OnDBusDaemonInit(bus_);
    return EX_OK;
  }

  int OnEventLoopStarted() override {
    bus_->AssertOnDBusThread();

    int ret = brillo::DBusDaemon::OnEventLoopStarted();
    if (ret != EX_OK)
      return ret;

    auto quit = base::BindOnce(&Daemon::Quit, weak_ptr_factory_.GetWeakPtr());
    return client_->StartFuseSession(std::move(quit));
  }

  void OnShutdown(int* exit_code) override {
    bus_->AssertOnDBusThread();

    DBusDaemon::OnShutdown(exit_code);
    client_.reset();
  }

 private:
  // Fuse mount: not owned.
  FuseMount* fuse_ = nullptr;

  // Fuse user-space client.
  std::unique_ptr<FuseBoxClient> client_;

  base::WeakPtrFactory<FuseBoxDaemon> weak_ptr_factory_;
};

int Run(char** mountpoint, fuse_chan* chan, int foreground) {
  LOG(INFO) << "fusebox " << *mountpoint << " [" << getpid() << "]";

  FuseMount fuse = FuseMount(mountpoint, chan);

  auto* commandline_options = base::CommandLine::ForCurrentProcess();
  fuse.opts = commandline_options->GetSwitchValueASCII("ll");
  fuse.debug = commandline_options->HasSwitch("debug");

  if (!foreground)
    LOG(INFO) << "fusebox fuse_daemonizing";
  fuse_daemonize(foreground);

  auto daemon = FuseBoxDaemon(&fuse);
  return daemon.Run();
}

}  // namespace fusebox

int main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  fuse_args args = FUSE_ARGS_INIT(argc, argv);
  char* mountpoint = nullptr;

  int foreground = 0;
  if (fuse_parse_cmdline(&args, &mountpoint, nullptr, &foreground) == -1) {
    PLOG(ERROR) << "fuse_parse_cmdline() failed";
    return EX_USAGE;
  }

  if (!mountpoint) {
    LOG(ERROR) << "fuse_parse_cmdline() mountpoint expected";
    return ENODEV;
  }

  fuse_chan* chan = fuse_mount(mountpoint, &args);
  if (!chan) {
    PLOG(ERROR) << "fuse_mount() [" << mountpoint << "] failed";
    return ENODEV;
  }

  int exit_code = fusebox::Run(&mountpoint, chan, foreground);

  if (!mountpoint) {  // Kernel removed the FUSE mountpoint: umount(8).
    exit_code = EX_OK;
  } else {
    fuse_unmount(mountpoint, nullptr);
  }

  return exit_code;
}
