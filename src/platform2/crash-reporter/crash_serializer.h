// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_CRASH_SERIALIZER_H_
#define CRASH_REPORTER_CRASH_SERIALIZER_H_

#include <memory>
#include <string>
#include <vector>

#include <base/time/clock.h>
#include <base/files/file_path.h>
#include <base/files/file.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "crash-reporter/crash_sender_base.h"
#include "crash-reporter/crash_sender_util.h"
#include "crash-reporter/crash_serializer.pb.h"

namespace crash_serializer {

// A helper class for serializing crashes. Its behaviors can be customized by
// the options struct.
class Serializer : public util::SenderBase {
 public:
  struct Options : public SenderBase::Options {
    // If true, fetch coredumps as well.
    bool fetch_coredumps;
    // Approximate largest proto size we will write in a single message.
    //
    // Defaults to 1MiB per
    // https://developers.google.com/protocol-buffers/docs/techniques#large-data
    // which says, "As a general rule of thumb, if you are dealing in messages
    // larger than a megabyte each, it may be time to consider an alternate
    // strategy."
    //
    // Exceptions / caveats:
    // * CrashInfo messages are exempt from this as we expect they'll be small.
    // * Messages may exceed this size by a few bytes, since we split based only
    //   on the large fields in a message (for instance, a blob or a core). If
    //   we start with a 2MiB blob, we'll split the blob across two messages.
    //   The additional metadata (e.g. crash_id, key, filename) may push the
    //   message just over 1MiB.
    size_t max_proto_bytes = 1 << 20;
  };
  Serializer(std::unique_ptr<base::Clock> clock, const Options& options);

  // Pick crash files to serialize.
  void PickCrashFiles(const base::FilePath& crash_dir,
                      std::vector<util::MetaFile>* to_send);

  // Serialize the given crashes to the out file
  void SerializeCrashes(const std::vector<util::MetaFile>& crash_meta_files);

  // For tests only. Set the serializer to write output to the specified file
  // instead of stdout.
  void set_output_for_testing(const base::FilePath& file) { out_ = file; }

 protected:
  // SenderBase method
  void RecordCrashRemoveReason(CrashRemoveReason reason) override;

 private:
  FRIEND_TEST(CrashSerializerParameterizedTest, SerializeCrash);
  FRIEND_TEST(CrashSerializerTest, WriteFetchCrashesResponse);
  FRIEND_TEST(CrashSerializerTest, WriteFetchCrashesResponse_WriteFail);
  FRIEND_TEST(CrashSerializerTest, WriteBlobs_Basic);
  FRIEND_TEST(CrashSerializerTest, WriteBlobs_ManySizes);
  FRIEND_TEST(CrashSerializerTest, WriteBlobs_Empty);
  FRIEND_TEST(CrashSerializerTest, WriteBlobs_Failure);
  FRIEND_TEST(CrashSerializerTest, WriteCoredump_Basic);
  FRIEND_TEST(CrashSerializerTest, WriteCoredump_LargerThanChunkSize);
  FRIEND_TEST(CrashSerializerTest, WriteCoredump_ManySizes);
  FRIEND_TEST(CrashSerializerTest, WriteCoredump_Nonexistent);

  // Serialize a single crash into the given outputs.
  // Populates |core_path| iff fetch_cores_ is true and the core file exists.
  // Does NOT read core into memory as it might be quite large.
  // Return true on success or false on failure.
  // Ignores nonexistent files in info.files, but fails if info.payload is
  // missing.
  bool SerializeCrash(const util::CrashDetails& details,
                      crash::CrashInfo* info,
                      std::vector<crash::CrashBlob>* blobs,
                      base::FilePath* core_path);

  // Write the given FetchCrashesResponse proto to |out_|.
  // The serialization format is:
  // The size of the serialized protobuf as a big-endian uint64_t,
  // followed by the serialized protobuf.
  // Format inspired by
  // https://developers.google.com/protocol-buffers/docs/techniques#streaming
  //
  // The 8 bytes for the size are _not_ counted in the size.
  // For example, if a protobuf serialized to the 4 bytes aabbccdd, the
  // overall serialized data would be:
  // 0000 0000 0000 0003 aabb ccdd
  // Returns true on a successful write and false otherwise.
  bool WriteFetchCrashesResponse(const crash::FetchCrashesResponse& crash_data);

  // Write the specified blobs to |out_|, chunking them based on
  // |max_message_size_bytes_|.
  bool WriteBlobs(int64_t crash_id, const std::vector<crash::CrashBlob>& blobs);

  // Read the core dump at the given path and write it to |out_|, chunking it
  // based on |max_message_size_bytes_|.
  bool WriteCoredump(int64_t crash_id, base::FilePath core_path);

  // Creates a `ScopedProcessingFileBase` object.
  std::unique_ptr<util::ScopedProcessingFileBase> MakeScopedProcessingFile(
      const base::FilePath& meta_file) override;

  base::FilePath out_;

  // True iff we should fetch core dumps.
  const bool fetch_cores_;

  // Largest proto size we will write in a single message. CrashInfo messages
  // are exempt from this limit as we generally expect they'll be small.
  const size_t max_message_size_bytes_;
};

}  // namespace crash_serializer

#endif  // CRASH_REPORTER_CRASH_SERIALIZER_H_
