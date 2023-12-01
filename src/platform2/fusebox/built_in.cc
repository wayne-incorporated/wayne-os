// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "fusebox/built_in.h"

#include <inttypes.h>
#include <utility>

#include <base/logging.h>
#include <base/time/time.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/message.h>

#include "fusebox/make_stat.h"

namespace fusebox {
namespace {

// kFuseStatusContentsLen equals strlen(kFuseStatusContentsPtr).
constexpr size_t kFuseStatusContentsLen = 3;
constexpr char kFuseStatusContentsPtr[] = "ok\n";
constexpr char kFuseStatusFilename[] = "fuse_status";
// INT64_MAX, 9223372036854775807, has 19 digits. The " micros\n" suffix adds a
// further 8 bytes.
constexpr size_t kPingContentsLen = 27;
constexpr char kPingFilename[] = "ping";

void clipToBounds(size_t& size, off_t& off, size_t max_size) {
  if ((off < 0) || (max_size <= off)) {
    size = 0;
    off = 0;
  } else if (size > (max_size - off)) {
    size = max_size - off;
  }
}

void BuiltInReadPingResponse(std::unique_ptr<BufferRequest> request,
                             base::TimeTicks start_ticks,
                             size_t size,
                             off_t off,
                             dbus::Response* response) {
  int64_t micros = (base::TimeTicks::Now() - start_ticks).InMicroseconds();
  if (micros < 0) {
    micros = 0;
  }
  char buffer[32];
  snprintf(buffer, sizeof(buffer), "%19" PRId64 " micros\n", micros);
  CHECK_EQ(kPingContentsLen, strlen(buffer));
  clipToBounds(size, off, kPingContentsLen);
  request->ReplyBuffer(buffer + off, size);
}

void BuiltInReadPing(scoped_refptr<dbus::ObjectProxy> dbus_proxy,
                     std::unique_ptr<BufferRequest> request,
                     size_t size,
                     off_t off) {
  // Issue a Stat2 call over D-Bus. The result of the Stat2 doesn't matter (and
  // should be an error for a subdir that doesn't exist). We just want to time
  // how long it takes to respond.
  Stat2RequestProto request_proto;
  request_proto.set_file_system_url("ping_subdir_should_not_exist");
  dbus::MethodCall method(kFuseBoxServiceInterface, kStat2Method);
  dbus::MessageWriter writer(&method);
  writer.AppendProtoAsArrayOfBytes(request_proto);
  dbus_proxy->CallMethod(
      &method, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT,
      base::BindOnce(&BuiltInReadPingResponse, std::move(request),
                     base::TimeTicks::Now(), size, off));
}

}  // namespace

void BuiltInEnsureNodes(InodeTable& itab) {
  itab.Ensure(INO_BUILT_IN, kFuseStatusFilename, 0, INO_BUILT_IN_FUSE_STATUS);
  itab.Ensure(INO_BUILT_IN, kPingFilename, 0, INO_BUILT_IN_PING);
}

void BuiltInGetStat(ino_t ino, struct stat* stat) {
  *stat = {0};
  switch (ino) {
    case INO_BUILT_IN_FUSE_STATUS:
      stat->st_size = kFuseStatusContentsLen;
      break;
    case INO_BUILT_IN_PING:
      stat->st_size = kPingContentsLen;
      break;
    default:
      return;
  }
  stat->st_dev = 1;
  stat->st_ino = ino;
  stat->st_mode = S_IFREG | 0444;
  stat->st_nlink = 1;
  stat->st_uid = kChronosUID;
  stat->st_gid = kChronosAccessGID;
}

void BuiltInLookup(std::unique_ptr<EntryRequest> request,
                   const std::string& name) {
  ino_t ino = 0;
  if (name == kFuseStatusFilename) {
    ino = INO_BUILT_IN_FUSE_STATUS;
  } else if (name == kPingFilename) {
    ino = INO_BUILT_IN_PING;
  } else {
    errno = request->ReplyError(ENOENT);
    PLOG(ERROR) << "BuiltInLookup";
    return;
  }

  fuse_entry_param entry = {0};
  entry.ino = ino;
  BuiltInGetStat(ino, &entry.attr);
  entry.attr_timeout = kStatTimeoutSeconds;
  entry.entry_timeout = kEntryTimeoutSeconds;
  request->ReplyEntry(entry);
}

void BuiltInRead(scoped_refptr<dbus::ObjectProxy> dbus_proxy,
                 std::unique_ptr<BufferRequest> request,
                 ino_t ino,
                 size_t size,
                 off_t off) {
  switch (ino) {
    case INO_BUILT_IN_FUSE_STATUS:
      clipToBounds(size, off, kFuseStatusContentsLen);
      request->ReplyBuffer(kFuseStatusContentsPtr + off, size);
      return;
    case INO_BUILT_IN_PING:
      BuiltInReadPing(std::move(dbus_proxy), std::move(request), size, off);
      return;
  }

  errno = request->ReplyError(ENOENT);
  PLOG(ERROR) << "BuiltInRead";
}

void BuiltInReadDir(off_t off, std::unique_ptr<DirEntryRequest> request) {
  static const std::pair<ino_t, const char*> entries[] = {
      {INO_BUILT_IN_FUSE_STATUS, kFuseStatusFilename},
      {INO_BUILT_IN_PING, kPingFilename},
  };
  static constexpr size_t n = sizeof(entries) / sizeof(entries[0]);

  for (size_t i = off; i < n; i++) {
    if (!request->AddEntry(
            {entries[i].first, entries[i].second, S_IFREG | 0444}, i + 1)) {
      break;
    }
  }
  request->ReplyDone();
}

}  // namespace fusebox
