// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "crash-reporter/crash_serializer.h"

#include <stdio.h>

#include <optional>
#include <string>
#include <utility>

#include <base/big_endian.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_util.h>
#include <base/threading/platform_thread.h>
#include <base/time/default_clock.h>
#include <base/time/time.h>

#include "crash-reporter/crash_sender_base.h"
#include "crash-reporter/crash_sender_util.h"
#include "crash-reporter/paths.h"
#include "crash-reporter/util.h"

namespace crash_serializer {

namespace {
void AddMetaField(crash::CrashInfo* info,
                  const std::string& key,
                  const std::string& value) {
  if (!base::IsStringUTF8(key)) {
    LOG(ERROR) << "key was not UTF8: " << key;
    return;
  }
  if (!base::IsStringUTF8(value)) {
    LOG(ERROR) << "value for key '" << key << "' was not UTF8";
    return;
  }
  crash::CrashMetadata* meta = info->add_fields();
  meta->set_key(key);
  meta->set_text(value);
}

std::optional<crash::CrashBlob> MakeBlob(const std::string& name,
                                         const base::FilePath& file) {
  if (!base::IsStringUTF8(name)) {
    LOG(ERROR) << "key was not UTF8: " << name;
    return std::nullopt;
  }
  std::string contents;
  if (!base::ReadFileToString(file, &contents)) {
    return std::nullopt;
  }
  crash::CrashBlob b;
  b.set_key(name);
  b.set_blob(contents);
  b.set_filename(file.BaseName().value());
  return b;
}

}  // namespace

Serializer::Serializer(std::unique_ptr<base::Clock> clock,
                       const Options& options)
    : util::SenderBase(std::move(clock), options),
      out_("/dev/stdout"),
      fetch_cores_(options.fetch_coredumps),
      max_message_size_bytes_(options.max_proto_bytes) {}

// The serializer doesn't remove crashes, so do nothing.
void Serializer::RecordCrashRemoveReason(CrashRemoveReason reason) {}

void Serializer::PickCrashFiles(const base::FilePath& crash_dir,
                                std::vector<util::MetaFile>* to_send) {
  std::vector<base::FilePath> meta_files = util::GetMetaFiles(crash_dir);

  for (const auto& meta_file : meta_files) {
    LOG(INFO) << "Checking metadata: " << meta_file.value();

    std::string reason;
    util::CrashInfo info;
    switch (EvaluateMetaFileMinimal(meta_file, /*allow_old_os_timestamps=*/true,
                                    &reason, &info,
                                    /*processing_file=*/nullptr)) {
      case kRemove:
        [[fallthrough]];  // Don't remove; rather, ignore the report.
      case kIgnore:
        LOG(INFO) << "Ignoring: " << reason;
        break;
      case kSend:
        to_send->push_back(std::make_pair(meta_file, std::move(info)));
        break;
      default:
        NOTREACHED();
    }
  }
}

void Serializer::SerializeCrashes(
    const std::vector<util::MetaFile>& crash_meta_files) {
  if (crash_meta_files.empty()) {
    return;
  }

  std::string client_id = util::GetClientId();

  base::File lock(AcquireLockFileOrDie());
  int64_t crash_id = -1;
  for (const auto& pair : crash_meta_files) {
    crash_id++;
    const base::FilePath& meta_file = pair.first;
    const util::CrashInfo& info = pair.second;
    LOG(INFO) << "Evaluating crash report: " << meta_file.value();

    base::TimeDelta sleep_time;
    if (!util::GetSleepTime(meta_file, /*max_spread_time=*/base::TimeDelta(),
                            hold_off_time_, &sleep_time)) {
      LOG(WARNING) << "Failed to compute sleep time for " << meta_file.value();
      continue;
    }

    LOG(INFO) << "Scheduled to send in " << sleep_time.InSeconds() << "s";
    lock.Close();  // Don't hold lock during sleep.
    if (!util::IsMock()) {
      base::PlatformThread::Sleep(sleep_time);
    } else if (!sleep_function_.is_null()) {
      sleep_function_.Run(sleep_time);
    }
    lock = AcquireLockFileOrDie();

    // Mark the crash as being processed so that if we crash, we don't try to
    // send the crash again.
    util::ScopedProcessingFile processing(meta_file);

    // User-specific crash reports become inaccessible if the user signs out
    // while sleeping, thus we need to check if the metadata is still
    // accessible.
    if (!base::PathExists(meta_file)) {
      LOG(INFO) << "Metadata is no longer accessible: " << meta_file.value();
      continue;
    }

    const util::CrashDetails details = {
        .meta_file = meta_file,
        .payload_file = info.payload_file,
        .payload_kind = info.payload_kind,
        .client_id = client_id,
        .metadata = info.metadata,
    };

    crash::FetchCrashesResponse resp;
    resp.set_crash_id(crash_id);
    std::vector<crash::CrashBlob> blobs;
    base::FilePath core_path;
    if (!SerializeCrash(details, resp.mutable_crash(), &blobs, &core_path)) {
      // If we cannot serialize the crash, give up -- there won't be anything to
      // write.
      LOG(ERROR) << "Failed to serialize " << meta_file.value();
      continue;
    }

    // Write the CrashInfo to output.
    if (!WriteFetchCrashesResponse(resp)) {
      // If we cannot write the CrashInfo, give up on the crash -- callers won't
      // be able to reconstruct anything useful from the report.
      LOG(ERROR) << "Failed to write CrashInfo proto for: " << meta_file.value()
                 << ". Giving up on this crash";
      continue;
    }

    if (!WriteBlobs(crash_id, blobs)) {
      // If this fails, keep trying to process the crash -- the coredump could
      // still be useful.
      LOG(ERROR) << "Failed to write blobs for " << meta_file.value();
    }

    if (!core_path.empty() && !WriteCoredump(crash_id, core_path)) {
      LOG(ERROR) << "Failed to write core for " << meta_file.value();
    }
  }
}

bool Serializer::SerializeCrash(const util::CrashDetails& details,
                                crash::CrashInfo* info,
                                std::vector<crash::CrashBlob>* blobs,
                                base::FilePath* core_path) {
  util::FullCrash crash = ReadMetaFile(details);

  // Add fields that are present directly in the FullCrash struct
  info->set_exec_name(crash.exec_name);
  AddMetaField(info, "board", crash.board);
  AddMetaField(info, "hwclass", crash.hwclass);
  info->set_prod(crash.prod);
  info->set_ver(crash.ver);
  info->set_sig(crash.sig);
  AddMetaField(info, "sig2", crash.sig);
  AddMetaField(info, "image_type", crash.image_type);
  AddMetaField(info, "boot_mode", crash.boot_mode);
  AddMetaField(info, "error_type", crash.error_type);
  AddMetaField(info, "guid", crash.guid);

  // Add fields from key_vals
  for (const auto& kv : crash.key_vals) {
    const std::string& key = kv.first;
    const std::string& val = kv.second;
    if (key == "in_progress_integration_test") {
      info->set_in_progress_integration_test(val);
    } else if (key == "collector") {
      info->set_collector(val);
    } else {
      AddMetaField(info, key, val);
    }
  }

  // Add payload file
  std::optional<crash::CrashBlob> payload =
      MakeBlob(crash.payload.first, crash.payload.second);
  if (!payload) {
    return false;
  }
  blobs->push_back(*payload);

  // Add files
  for (const auto& kv : crash.files) {
    std::optional<crash::CrashBlob> blob = MakeBlob(kv.first, kv.second);
    if (blob) {
      blobs->push_back(*blob);
    }
  }

  if (fetch_cores_) {
    base::FilePath maybe_core = details.meta_file.ReplaceExtension(".core");
    if (base::PathExists(maybe_core)) {
      *core_path = maybe_core;
    }
  }

  return true;
}

bool Serializer::WriteFetchCrashesResponse(
    const crash::FetchCrashesResponse& crash_data) {
  // Initialize string with the size and then append the proto to that so that
  // we get the data in a single buffer with no extra copies.
  size_t size = crash_data.ByteSizeLong();
  // Convert to a fixed size to ensure a consistent serialization format.
  static_assert(sizeof(size_t) <= sizeof(uint64_t),
                "size_t is too big to fit in 8 bytes");
  uint64_t size_uint64 = size;

  char size_bytes[sizeof(size_uint64)];
  base::WriteBigEndian(size_bytes, size_uint64);

  std::string buf(size_bytes, size_bytes + sizeof(size_uint64));
  if (!crash_data.AppendToString(&buf)) {
    LOG(ERROR) << "Failed to serialize proto to string";
    return false;
  }

  if (!base::AppendToFile(out_, buf)) {
    PLOG(ERROR) << "Failed to append";
    return false;
  }
  CHECK_EQ(buf.size(), size + sizeof(size_uint64));
  return true;
}

bool Serializer::WriteBlobs(int64_t crash_id,
                            const std::vector<crash::CrashBlob>& blobs) {
  crash::FetchCrashesResponse resp;
  resp.set_crash_id(crash_id);
  bool success = true;
  for (const auto& blob : blobs) {
    size_t actual_size = blob.blob().size();
    // Divide and round up to calculate the number of protos to split this
    // blob into.
    int proto_count =
        (actual_size + max_message_size_bytes_ - 1) / max_message_size_bytes_;

    crash::CrashBlob* send_blob = resp.mutable_blob();
    send_blob->set_key(blob.key());
    send_blob->set_filename(blob.filename());
    size_t offset = 0;
    for (int i = 0; i < proto_count; i++) {
      // Re-retrieve the pointer here because WriteFetchCrashesResponse might
      // invalidate it; see
      // https://developers.google.com/protocol-buffers/docs/reference/cpp-generated#fields
      send_blob = resp.mutable_blob();
      CHECK_LE(offset, blob.blob().size());
      send_blob->set_blob(blob.blob().substr(offset, max_message_size_bytes_));

      if (!WriteFetchCrashesResponse(resp)) {
        LOG(ERROR) << "Failed to write blob: " << blob.key()
                   << " starting at offset: " << offset;
        // Don't continue with this blob -- even if we succeed at sending a
        // later chunk, callers won't be able to correctly reassemble the
        // data.
        success = false;
        break;
      }
      offset += max_message_size_bytes_;
    }
  }
  return success;
}

bool Serializer::WriteCoredump(int64_t crash_id, base::FilePath core_path) {
  crash::FetchCrashesResponse resp;
  resp.set_crash_id(crash_id);

  base::File core_file(core_path,
                       base::File::FLAG_OPEN | base::File::FLAG_READ);
  if (!core_file.IsValid()) {
    LOG(ERROR) << "Failed to open " << core_path.value() << " for reading: "
               << base::File::ErrorToString(core_file.error_details());
    return false;
  }

  int64_t size = core_file.GetLength();
  if (size < 0) {
    LOG(ERROR) << "Failed to get size for core file: " << core_path.value()
               << ": " << base::File::ErrorToString(core_file.error_details());
    return false;
  } else if (size == 0) {
    LOG(WARNING) << "Coredump " << core_path.value()
                 << " is empty. Proceeding anyway.";
  }

  int64_t total_read = 0;
  while (total_read < size) {
    std::vector<char> buf(max_message_size_bytes_);
    // Don't read the entire core into memory at once, as it could be multiple
    // GBs.
    int read = core_file.Read(total_read, buf.data(), max_message_size_bytes_);
    if (read < 0) {
      LOG(ERROR) << "Failed to read: " << core_path.value()
                 << "at offset: " << total_read << ": "
                 << base::File::ErrorToString(core_file.error_details());
      // Don't continue reading the core -- even if later calls succeed, the
      // caller won't be able to correctly reassemble the coredump.
      return false;
    }

    resp.set_core(buf.data(), read);
    if (!WriteFetchCrashesResponse(resp)) {
      LOG(ERROR) << "Failed to write core dump at offset " << total_read;
      // Don't continue reading the core -- even if later calls succeed, the
      // caller won't be able to correctly reassemble the coredump.
      return false;
    }

    total_read += read;
  }
  return true;
}

std::unique_ptr<util::ScopedProcessingFileBase>
Serializer::MakeScopedProcessingFile(const base::FilePath& meta_file) {
  return std::make_unique<util::ScopedProcessingFile>(meta_file);
}
}  // namespace crash_serializer
