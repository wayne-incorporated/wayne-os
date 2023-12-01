// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/crash_serializer.h"

#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <inttypes.h>

#include <base/big_endian.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/stringprintf.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "crash-reporter/crash_sender_base.h"
#include "crash-reporter/crash_sender_paths.h"
#include "crash-reporter/crash_serializer.pb.h"
#include "crash-reporter/paths.h"
#include "crash-reporter/test_util.h"

using test_util::kFakeClientId;

namespace crash_serializer {
namespace {

// Set the file flag which indicates we are mocking crash sending, either
// successfully or as a failure.
bool SetMockCrashSending(bool success) {
  util::g_force_is_mock = true;
  util::g_force_is_mock_successful = success;
  return base::CreateDirectory(
      paths::Get(paths::ChromeCrashLog::Get()).DirName());
}

}  // namespace

class CrashSerializerTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    test_dir_ = temp_dir_.GetPath();
    paths::SetPrefixForTesting(test_dir_);

    // Make sure the directory for the lock file exists.
    const base::FilePath lock_file_path =
        paths::Get(paths::kCrashSenderLockFile);
    const base::FilePath lock_file_directory = lock_file_path.DirName();
    ASSERT_TRUE(base::CreateDirectory(lock_file_directory));
  }

  void TearDown() override { paths::SetPrefixForTesting(base::FilePath()); }

  // Creates a file at |file_path| with contents |content| and sets its access
  // and modification time to |timestamp|.
  bool CreateFile(const base::FilePath& file_path,
                  base::StringPiece content,
                  base::Time timestamp) {
    if (!test_util::CreateFile(file_path, content))
      return false;

    if (!test_util::TouchFileHelper(file_path, timestamp))
      return false;

    return true;
  }

  // Creates test crash files in |crash_directory|. Returns true on success.
  bool CreateTestCrashFiles(const base::FilePath& crash_directory) {
    const base::Time now = test_util::GetDefaultTime();
    const base::TimeDelta hour = base::Hours(1);

    // Choose timestamps so that the return value of GetMetaFiles() is sorted
    // per timestamps correctly.
    const base::Time old_os_meta_time = now - base::Days(200);
    const base::Time good_meta_time = now - hour * 4;
    const base::Time absolute_meta_time = now - hour * 3;
    const base::Time uploaded_meta_time = now - hour * 2;
    const base::Time recent_os_meta_time = now - hour;
    const base::Time devcore_meta_time = now;

    // These should be serialized, since the payload is a known kind and exists.
    good_meta_ = crash_directory.Append("good.meta");
    good_log_ = crash_directory.Append("good.log");
    if (!CreateFile(good_meta_, "payload=good.log\ndone=1\n", good_meta_time))
      return false;
    if (!CreateFile(good_log_, "", now))
      return false;

    // These should be serialized, the payload path is absolute but should be
    // handled properly.
    absolute_meta_ = crash_directory.Append("absolute.meta");
    absolute_log_ = crash_directory.Append("absolute.log");
    if (!CreateFile(absolute_meta_,
                    "payload=" + absolute_log_.value() + "\n" + "done=1\n",
                    absolute_meta_time))
      return false;
    if (!CreateFile(absolute_log_, "", now))
      return false;

    // These should be serialized, even though the `alreadyuploaded` file
    // exists.
    uploaded_meta_ = crash_directory.Append("uploaded.meta");
    uploaded_log_ = crash_directory.Append("uploaded.log");
    uploaded_already_ = crash_directory.Append("uploaded.alreadyuploaded");
    if (!CreateFile(uploaded_meta_, "payload=uploaded.log\ndone=1\n",
                    uploaded_meta_time))
      return false;
    if (!CreateFile(uploaded_log_, "", now))
      return false;
    if (!CreateFile(uploaded_already_, "", now))
      return false;

    // This should be ignored as corrupt. Payload can't be /.
    root_payload_meta_ = crash_directory.Append("root_payload.meta");
    if (!test_util::CreateFile(root_payload_meta_,
                               "payload=/\n"
                               "done=1\n"))
      return false;

    // These should be serialized -- serializing devcore files is always OK
    // (as opposed to sending them, which is only sometimes okay).
    devcore_meta_ = crash_directory.Append("devcore.meta");
    devcore_devcore_ = crash_directory.Append("devcore.devcore");
    if (!CreateFile(devcore_meta_,
                    "payload=devcore.devcore\n"
                    "done=1\n",
                    devcore_meta_time))
      return false;
    if (!CreateFile(devcore_devcore_, "", now))
      return false;

    // This should be ignored, since metadata is corrupted.
    corrupted_meta_ = crash_directory.Append("corrupted.meta");
    if (!CreateFile(corrupted_meta_, "!@#$%^&*\ndone=1\n", now))
      return false;

    // This should be ignored, since no payload info is recorded.
    empty_meta_ = crash_directory.Append("empty.meta");
    if (!CreateFile(empty_meta_, "done=1\n", now))
      return false;

    // This should be ignored, since the payload file does not exist.
    nonexistent_meta_ = crash_directory.Append("nonexistent.meta");
    if (!CreateFile(nonexistent_meta_,
                    "payload=nonexistent.log\n"
                    "done=1\n",
                    now))
      return false;

    // These should be ignored, since the payload is an unknown kind.
    unknown_meta_ = crash_directory.Append("unknown.meta");
    unknown_xxx_ = crash_directory.Append("unknown.xxx");
    if (!CreateFile(unknown_meta_,
                    "payload=unknown.xxx\n"
                    "done=1\n",
                    now))
      return false;
    if (!CreateFile(unknown_xxx_, "", now))
      return false;

    // This should be ignored, since it's incomplete.
    old_incomplete_meta_ = crash_directory.Append("old_incomplete.meta");
    if (!CreateFile(old_incomplete_meta_, "payload=good.log\n", now))
      return false;
    if (!test_util::TouchFileHelper(old_incomplete_meta_, now - hour * 24))
      return false;

    // This should be ignored, since it's incomplete.
    new_incomplete_meta_ = crash_directory.Append("new_incomplete.meta");
    if (!CreateFile(new_incomplete_meta_, "payload=nonexistent.log\n", now))
      return false;

    // This should be serialized since the OS timestamp is recent.
    recent_os_meta_ = crash_directory.Append("recent_os.meta");
    if (!CreateFile(recent_os_meta_,
                    base::StringPrintf(
                        "payload=recent_os.log\n"
                        "os_millis=%" PRId64 "\n"
                        "done=1\n",
                        (now - base::Time::UnixEpoch()).InMilliseconds()),
                    recent_os_meta_time)) {
      return false;
    }
    recent_os_log_ = crash_directory.Append("recent_os.log");
    if (!CreateFile(recent_os_log_, "", now))
      return false;

    // This should be serialized despite the old OS timestamp.
    old_os_meta_ = crash_directory.Append("old_os.meta");
    if (!CreateFile(old_os_meta_,
                    base::StringPrintf(
                        "payload=good.log\n"
                        "os_millis=%" PRId64 "\n"
                        "done=1\n",
                        ((now - base::Time::UnixEpoch()) - base::Days(200))
                            .InMilliseconds()),
                    old_os_meta_time)) {
      return false;
    }

    // Create large metadata with the size of 1MiB + 1byte. This should be
    // ignored as it's too big.
    large_meta_ = crash_directory.Append("large.meta");
    if (!CreateFile(large_meta_, std::string(1024 * 1024 + 1, 'x'), now)) {
      return false;
    }

    return true;
  }

  base::ScopedTempDir temp_dir_;
  base::FilePath test_dir_;

  base::FilePath good_meta_;
  base::FilePath good_log_;
  base::FilePath absolute_meta_;
  base::FilePath absolute_log_;
  base::FilePath uploaded_meta_;
  base::FilePath uploaded_log_;
  base::FilePath uploaded_already_;
  base::FilePath root_payload_meta_;
  base::FilePath devcore_meta_;
  base::FilePath devcore_devcore_;
  base::FilePath empty_meta_;
  base::FilePath corrupted_meta_;
  base::FilePath nonexistent_meta_;
  base::FilePath unknown_meta_;
  base::FilePath unknown_xxx_;
  base::FilePath old_incomplete_meta_;
  base::FilePath new_incomplete_meta_;
  base::FilePath recent_os_meta_;
  base::FilePath recent_os_log_;
  base::FilePath old_os_meta_;
  base::FilePath large_meta_;
};

TEST_F(CrashSerializerTest, PickCrashFiles) {
  Serializer::Options options;
  Serializer serializer(std::make_unique<test_util::AdvancingClock>(), options);

  const base::FilePath crash_directory =
      paths::Get(paths::kSystemCrashDirectory);
  ASSERT_TRUE(CreateDirectory(crash_directory));
  ASSERT_TRUE(CreateTestCrashFiles(crash_directory));

  std::vector<util::MetaFile> to_serialize;
  serializer.PickCrashFiles(crash_directory, &to_serialize);
  // Everything should still exist
  EXPECT_TRUE(base::PathExists(good_meta_));
  EXPECT_TRUE(base::PathExists(good_log_));
  EXPECT_TRUE(base::PathExists(absolute_meta_));
  EXPECT_TRUE(base::PathExists(absolute_log_));
  EXPECT_TRUE(base::PathExists(uploaded_meta_));
  EXPECT_TRUE(base::PathExists(uploaded_log_));
  EXPECT_TRUE(base::PathExists(uploaded_already_));
  EXPECT_TRUE(base::PathExists(root_payload_meta_));
  EXPECT_TRUE(base::PathExists(devcore_meta_));
  EXPECT_TRUE(base::PathExists(devcore_devcore_));
  EXPECT_TRUE(base::PathExists(empty_meta_));
  EXPECT_TRUE(base::PathExists(corrupted_meta_));
  EXPECT_TRUE(base::PathExists(nonexistent_meta_));
  EXPECT_TRUE(base::PathExists(unknown_meta_));
  EXPECT_TRUE(base::PathExists(unknown_xxx_));
  EXPECT_TRUE(base::PathExists(old_incomplete_meta_));
  EXPECT_TRUE(base::PathExists(new_incomplete_meta_));
  EXPECT_TRUE(base::PathExists(recent_os_meta_));
  EXPECT_TRUE(base::PathExists(recent_os_log_));
  EXPECT_TRUE(base::PathExists(old_os_meta_));
  EXPECT_TRUE(base::PathExists(large_meta_));

  // All but the "absolute path" meta should be accepted
  ASSERT_EQ(5, to_serialize.size());
  // Sort the reports to allow for deterministic testing
  util::SortReports(&to_serialize);
  EXPECT_EQ(old_os_meta_.value(), to_serialize[0].first.value());
  EXPECT_EQ(good_meta_.value(), to_serialize[1].first.value());
  EXPECT_EQ(uploaded_meta_.value(), to_serialize[2].first.value());
  EXPECT_EQ(recent_os_meta_.value(), to_serialize[3].first.value());
  EXPECT_EQ(devcore_meta_.value(), to_serialize[4].first.value());
}

TEST_F(CrashSerializerTest, SerializeCrashes) {
  std::vector<util::MetaFile> crashes_to_serialize;

  // Establish the client ID.
  ASSERT_TRUE(test_util::CreateClientIdFile());

  // Set up mock sending so we use the fake sleep function
  ASSERT_TRUE(SetMockCrashSending(true));

  // Create the system crash directory, and crash files in it.
  const base::FilePath system_dir = paths::Get(paths::kSystemCrashDirectory);
  ASSERT_TRUE(base::CreateDirectory(system_dir));
  const base::FilePath system_meta_file = system_dir.Append("0.0.0.0.0.meta");
  const base::FilePath system_log = system_dir.Append("0.0.0.0.0.log");
  const base::FilePath system_processing =
      system_dir.Append("0.0.0.0.0.processing");
  const char system_meta[] =
      "payload=0.0.0.0.0.log\n"
      "exec_name=exec_foo\n"
      "fake_report_id=123\n"
      "upload_var_prod=foo\n"
      "done=1\n"
      "upload_var_reportTimeMillis=1000000\n";
  ASSERT_TRUE(test_util::CreateFile(system_meta_file, system_meta));
  ASSERT_TRUE(test_util::CreateFile(system_log, "system log data"));
  util::CrashInfo system_info;
  EXPECT_TRUE(system_info.metadata.LoadFromString(system_meta));
  system_info.payload_file = system_log.BaseName();
  system_info.payload_kind = "log";
  EXPECT_TRUE(base::Time::FromString("25 Apr 2018 1:23:44 GMT",
                                     &system_info.last_modified));
  crashes_to_serialize.emplace_back(system_meta_file, std::move(system_info));

  // Create a user crash directory, and crash files in it.
  const base::FilePath user_dir = paths::Get("/home/user/hash/crash");
  ASSERT_TRUE(base::CreateDirectory(user_dir));
  const base::FilePath user_meta_file = user_dir.Append("0.0.0.0.0.meta");
  const base::FilePath user_log = user_dir.Append("0.0.0.0.0.log");
  const base::FilePath user_core = user_dir.Append("0.0.0.0.0.core");
  const base::FilePath user_processing =
      user_dir.Append("0.0.0.0.0.processing");
  const char user_meta[] =
      "payload=0.0.0.0.0.log\n"
      "exec_name=exec_bar\n"
      "fake_report_id=456\n"
      "upload_var_prod=bar\n"
      "done=1\n"
      "upload_var_reportTimeMillis=2000000\n";
  ASSERT_TRUE(test_util::CreateFile(user_meta_file, user_meta));
  ASSERT_TRUE(test_util::CreateFile(user_log, "user log data"));
  ASSERT_TRUE(test_util::CreateFile(user_core, "user core"));
  util::CrashInfo user_info;
  EXPECT_TRUE(user_info.metadata.LoadFromString(user_meta));
  user_info.payload_file = user_log.BaseName();  // Payloads are relative
  user_info.payload_kind = "log";
  EXPECT_TRUE(base::Time::FromString("25 Apr 2018 1:24:01 GMT",
                                     &user_info.last_modified));
  crashes_to_serialize.emplace_back(user_meta_file, std::move(user_info));

  // Set up the serializer.
  std::vector<base::TimeDelta> sleep_times;
  Serializer::Options options;
  options.fetch_coredumps = true;
  options.sleep_function =
      base::BindRepeating(&test_util::FakeSleep, &sleep_times);
  Serializer serializer(std::make_unique<test_util::AdvancingClock>(), options);

  base::FilePath out = test_dir_.Append("SerializeCrashes");
  ASSERT_TRUE(test_util::CreateFile(out, ""));
  serializer.set_output_for_testing(out);

  serializer.SerializeCrashes(crashes_to_serialize);

  EXPECT_EQ(2, sleep_times.size());

  // We shouldn't be processing any crashes still.
  EXPECT_FALSE(base::PathExists(system_processing));
  EXPECT_FALSE(base::PathExists(user_processing));

  std::string written;
  ASSERT_TRUE(base::ReadFileToString(out, &written));

  // Deserialize the data.
  std::vector<crash::FetchCrashesResponse> resps;
  uint64_t pos = 0;
  while (pos < written.size()) {
    std::string size_str = written.substr(pos, sizeof(uint64_t));
    uint64_t size;
    base::ReadBigEndian(reinterpret_cast<const uint8_t*>(size_str.data()),
                        &size);
    pos += sizeof(size);

    // All of our payloads are small, so don't need to combine subsequent
    // response protos into one.
    crash::FetchCrashesResponse resp;
    resp.ParseFromString(written.substr(pos, size));
    resps.push_back(resp);

    pos += size;
  }
  ASSERT_EQ(resps.size(), 5);

  // Verify system crash
  EXPECT_EQ(resps[0].crash_id(), 0);
  ASSERT_TRUE(resps[0].has_crash());
  EXPECT_EQ(resps[0].crash().exec_name(), "exec_foo");
  EXPECT_EQ(resps[0].crash().prod(), "foo");
  EXPECT_EQ(resps[0].crash().ver(), "undefined");
  EXPECT_EQ(resps[0].crash().sig(), "");
  EXPECT_EQ(resps[0].crash().in_progress_integration_test(), "");
  EXPECT_EQ(resps[0].crash().collector(), "");
  EXPECT_EQ(resps[0].crash().collector(), "");
  int num_fields = resps[0].crash().fields_size();
  ASSERT_GE(num_fields, 7);
  EXPECT_EQ(resps[0].crash().fields(6).key(), "guid");
  EXPECT_EQ(resps[0].crash().fields(6).text(), kFakeClientId);

  EXPECT_EQ(resps[1].crash_id(), 0);
  ASSERT_TRUE(resps[1].has_blob());
  EXPECT_EQ(resps[1].blob().key(), "upload_file_log");
  EXPECT_EQ(resps[1].blob().filename(), "0.0.0.0.0.log");
  EXPECT_EQ(resps[1].blob().blob(), "system log data");

  // Verify user crash
  EXPECT_EQ(resps[2].crash_id(), 1);
  ASSERT_TRUE(resps[2].has_crash());
  EXPECT_EQ(resps[2].crash().exec_name(), "exec_bar");
  EXPECT_EQ(resps[2].crash().prod(), "bar");
  EXPECT_EQ(resps[2].crash().ver(), "undefined");
  EXPECT_EQ(resps[2].crash().sig(), "");
  EXPECT_EQ(resps[2].crash().in_progress_integration_test(), "");
  EXPECT_EQ(resps[2].crash().collector(), "");
  num_fields = resps[2].crash().fields_size();
  ASSERT_GE(num_fields, 7);
  EXPECT_EQ(resps[2].crash().fields(6).key(), "guid");
  EXPECT_EQ(resps[2].crash().fields(6).text(), kFakeClientId);

  EXPECT_EQ(resps[3].crash_id(), 1);
  ASSERT_TRUE(resps[3].has_blob());
  EXPECT_EQ(resps[3].blob().key(), "upload_file_log");
  EXPECT_EQ(resps[3].blob().filename(), "0.0.0.0.0.log");
  EXPECT_EQ(resps[3].blob().blob(), "user log data");
  EXPECT_EQ(resps[4].crash_id(), 1);

  EXPECT_EQ(resps[4].crash_id(), 1);
  // proto3 doesn't create has_XXX methods for string oneof fields, so don't
  // check has_core()
  EXPECT_EQ(resps[4].core(), "user core");

  // The uploaded crash files should not be removed.
  EXPECT_TRUE(base::PathExists(system_meta_file));
  EXPECT_TRUE(base::PathExists(system_log));
  EXPECT_TRUE(base::PathExists(user_meta_file));
  EXPECT_TRUE(base::PathExists(user_log));
  EXPECT_TRUE(base::PathExists(user_core));
}

TEST_F(CrashSerializerTest, WriteFetchCrashesResponse) {
  crash::FetchCrashesResponse resp;
  resp.set_crash_id(0x1234'5678'9abc'def0);
  resp.set_core(std::string("\00\x11\x22\x33", 4));
  std::string expected;
  resp.SerializeToString(&expected);

  Serializer::Options options;
  Serializer serializer(std::make_unique<test_util::AdvancingClock>(), options);

  base::FilePath out = test_dir_.Append("WriteFetchCrashesResponse");
  ASSERT_TRUE(test_util::CreateFile(out, ""));
  serializer.set_output_for_testing(out);

  ASSERT_TRUE(serializer.WriteFetchCrashesResponse(resp));
  std::string actual;
  ASSERT_TRUE(base::ReadFileToString(out, &actual));

  // Read the size and verify that it matches what we expect.
  std::string actual_size_str = actual.substr(0, sizeof(uint64_t));
  uint64_t actual_size;
  base::ReadBigEndian(reinterpret_cast<const uint8_t*>(actual_size_str.data()),
                      &actual_size);
  EXPECT_EQ(expected.size(), actual_size);

  // Note that we don't verify that the size in bytes matches, because to do so
  // we'd either have to:
  // 1) Reproduce the logic in WriteFetchCrashesResponse that converts the size
  // to a string, or
  // 2) Hard-code an expected size, which would be brittle and subject to
  // breakage if the protobuf serialization format changes at all in future.
  EXPECT_EQ(expected, actual.substr(sizeof(uint64_t)));
}

TEST_F(CrashSerializerTest, WriteFetchCrashesResponse_WriteFail) {
  crash::FetchCrashesResponse resp;
  resp.set_crash_id(42);
  resp.set_core("asdf");

  Serializer::Options options;
  Serializer serializer(std::make_unique<test_util::AdvancingClock>(), options);

  base::FilePath out = test_dir_.Append("WriteFetchCrashesResponse_WriteFail");
  // Don't create file -- Append in serializer will fail.
  serializer.set_output_for_testing(out);

  EXPECT_FALSE(serializer.WriteFetchCrashesResponse(resp));
}

TEST_F(CrashSerializerTest, WriteBlobs_Basic) {
  std::vector<crash::CrashBlob> blobs;
  crash::CrashBlob blob1;
  blob1.set_key("1701d");
  blob1.set_filename("jean.luc.picard");
  blob1.set_blob("boldly go");
  blobs.push_back(blob1);

  crash::CrashBlob blob2;
  blob2.set_key("nx01");
  blob2.set_filename("jonathan.archer");
  blob2.set_blob("temporal cold war");
  blobs.push_back(blob2);

  Serializer::Options options;
  Serializer serializer(std::make_unique<test_util::AdvancingClock>(), options);

  base::FilePath out = test_dir_.Append("WriteBlobs_Basic");
  ASSERT_TRUE(test_util::CreateFile(out, ""));
  serializer.set_output_for_testing(out);

  ASSERT_TRUE(serializer.WriteBlobs(/*crash_id=*/42, blobs));
  std::string actual;
  ASSERT_TRUE(base::ReadFileToString(out, &actual));

  uint64_t pos = 0;
  for (const auto& blob : blobs) {
    std::string actual_size_str = actual.substr(pos, sizeof(uint64_t));
    pos += sizeof(uint64_t);
    uint64_t actual_size;
    base::ReadBigEndian(
        reinterpret_cast<const uint8_t*>(actual_size_str.data()), &actual_size);
    crash::FetchCrashesResponse resp;
    resp.ParseFromString(actual.substr(pos, actual_size));
    EXPECT_EQ(resp.crash_id(), 42);
    EXPECT_EQ(resp.blob().key(), blob.key());
    EXPECT_EQ(resp.blob().filename(), blob.filename());
    EXPECT_EQ(resp.blob().blob(), blob.blob());
    pos += actual_size;
  }
  EXPECT_EQ(pos, actual.size());  // should be at end of string
}

TEST_F(CrashSerializerTest, WriteBlobs_ManySizes) {
  Serializer::Options options;
  options.max_proto_bytes = 18;  // choose an arbitrary (but small) maximum
  Serializer serializer(std::make_unique<test_util::AdvancingClock>(), options);

  base::FilePath out = test_dir_.Append("WriteBlobs_ManySizes");
  ASSERT_TRUE(test_util::CreateFile(out, ""));
  serializer.set_output_for_testing(out);

  std::vector<crash::CrashBlob> blobs;
  for (int i = 0; i < options.max_proto_bytes * 5; i++) {
    crash::CrashBlob blob;
    blob.set_key(base::StringPrintf("%d", i));
    blob.set_filename(base::StringPrintf("%d.blob", i));
    blob.set_blob(std::string('A', i));
    blobs.push_back(blob);
  }

  ASSERT_TRUE(serializer.WriteBlobs(/*crash_id=*/0xc0de, blobs));
  std::string actual;
  ASSERT_TRUE(base::ReadFileToString(out, &actual));

  std::vector<crash::CrashBlob> actual_blobs;
  uint64_t pos = 0;
  while (pos < actual.size()) {
    std::string actual_size_str = actual.substr(pos, sizeof(uint64_t));
    pos += sizeof(uint64_t);
    uint64_t actual_size;
    base::ReadBigEndian(
        reinterpret_cast<const uint8_t*>(actual_size_str.data()), &actual_size);
    crash::FetchCrashesResponse resp;
    resp.ParseFromString(actual.substr(pos, actual_size));
    pos += actual_size;

    EXPECT_EQ(resp.crash_id(), 0xc0de);

    crash::CrashBlob blob = resp.blob();
    EXPECT_LE(blob.blob().size(), options.max_proto_bytes);
    if (actual_blobs.size() > 0 && actual_blobs.back().key() == blob.key()) {
      EXPECT_EQ(actual_blobs.back().filename(), blob.filename());
      actual_blobs.back().set_blob(actual_blobs.back().blob() + blob.blob());
    } else {
      actual_blobs.push_back(blob);
    }
  }

  ASSERT_EQ(actual_blobs.size(), blobs.size());
  for (int i = 0; i < actual_blobs.size(); i++) {
    EXPECT_EQ(actual_blobs[i].key(), blobs[i].key());
    EXPECT_EQ(actual_blobs[i].filename(), blobs[i].filename());
    EXPECT_EQ(actual_blobs[i].blob(), blobs[i].blob());
  }
}

TEST_F(CrashSerializerTest, WriteBlobs_Empty) {
  Serializer::Options options;
  Serializer serializer(std::make_unique<test_util::AdvancingClock>(), options);

  base::FilePath out = test_dir_.Append("WriteBlobs_Empty");
  // Don't create file -- we shouldn't write to it.
  serializer.set_output_for_testing(out);

  std::vector<crash::CrashBlob> blobs;
  EXPECT_TRUE(serializer.WriteBlobs(/*crash_id=*/0, blobs));
}

TEST_F(CrashSerializerTest, WriteBlobs_Failure) {
  Serializer::Options options;
  Serializer serializer(std::make_unique<test_util::AdvancingClock>(), options);

  base::FilePath out = test_dir_.Append("WriteBlobs_Failure");
  // Don't create file -- Append in serializer will fail.
  serializer.set_output_for_testing(out);

  std::vector<crash::CrashBlob> blobs;
  crash::CrashBlob blob;
  blob.set_key("key mckeyface");
  blob.set_filename("key.face");
  blob.set_blob("asdf");
  blobs.push_back(blob);
  EXPECT_FALSE(serializer.WriteBlobs(/*crash_id=*/1, blobs));
}

TEST_F(CrashSerializerTest, WriteCoredump_Basic) {
  // Core dumps can and do have null bytes in them.
  std::string core_contents("\x00\x11\x22\x33", 4);
  ASSERT_EQ(core_contents.size(), 4);

  crash::FetchCrashesResponse resp;
  resp.set_crash_id(0x1234'5678'9abc'def0);
  resp.set_core(core_contents);
  std::string expected;
  resp.SerializeToString(&expected);

  base::FilePath core = test_dir_.Append("core");
  ASSERT_TRUE(test_util::CreateFile(core, core_contents));

  Serializer::Options options;
  Serializer serializer(std::make_unique<test_util::AdvancingClock>(), options);

  base::FilePath out = test_dir_.Append("WriteCoredump");
  ASSERT_TRUE(test_util::CreateFile(out, ""));
  serializer.set_output_for_testing(out);

  ASSERT_TRUE(
      serializer.WriteCoredump(/*crash_id=*/0x1234'5678'9abc'def0, core));
  std::string actual;
  ASSERT_TRUE(base::ReadFileToString(out, &actual));

  std::string actual_size_str = actual.substr(0, sizeof(uint64_t));
  uint64_t actual_size;
  base::ReadBigEndian(reinterpret_cast<const uint8_t*>(actual_size_str.data()),
                      &actual_size);
  EXPECT_EQ(expected.size(), actual_size);
  EXPECT_EQ(expected, actual.substr(sizeof(uint64_t)));
}

TEST_F(CrashSerializerTest, WriteCoredump_LargerThanChunkSize) {
  std::string core_contents("0123456789abcdef");
  base::FilePath core = test_dir_.Append("core");
  ASSERT_TRUE(test_util::CreateFile(core, core_contents));

  crash::FetchCrashesResponse resp1;
  resp1.set_crash_id(1);
  resp1.set_core("0123456789");
  std::string expected1;
  resp1.SerializeToString(&expected1);

  crash::FetchCrashesResponse resp2;
  resp2.set_crash_id(1);  // same crash id
  resp2.set_core("abcdef");
  std::string expected2;
  resp2.SerializeToString(&expected2);

  Serializer::Options options;
  options.max_proto_bytes = 10;
  Serializer serializer(std::make_unique<test_util::AdvancingClock>(), options);

  base::FilePath out = test_dir_.Append("WriteCoredump_LargerThanChunkSize");
  ASSERT_TRUE(test_util::CreateFile(out, ""));
  serializer.set_output_for_testing(out);

  ASSERT_TRUE(serializer.WriteCoredump(/*crash_id=*/1, core));
  std::string actual;
  ASSERT_TRUE(base::ReadFileToString(out, &actual));

  uint64_t pos = 0;
  std::string actual_size_str1 = actual.substr(0, sizeof(uint64_t));
  pos += sizeof(uint64_t);
  uint64_t actual_size1;
  base::ReadBigEndian(reinterpret_cast<const uint8_t*>(actual_size_str1.data()),
                      &actual_size1);
  EXPECT_EQ(expected1.size(), actual_size1);
  EXPECT_EQ(expected1, actual.substr(pos, actual_size1));
  pos += actual_size1;

  std::string actual_size_str2 = actual.substr(pos, sizeof(uint64_t));
  pos += sizeof(uint64_t);
  uint64_t actual_size2;
  base::ReadBigEndian(reinterpret_cast<const uint8_t*>(actual_size_str2.data()),
                      &actual_size2);
  EXPECT_EQ(expected2.size(), actual_size2);
  EXPECT_EQ(expected2, actual.substr(pos));
}

// Verify that core dump splitting works at many different core sizes (with
// different relationships to the chunk size).
TEST_F(CrashSerializerTest, WriteCoredump_ManySizes) {
  const int kChunkSize = 10;
  Serializer::Options options;
  options.max_proto_bytes = kChunkSize;
  Serializer serializer(std::make_unique<test_util::AdvancingClock>(), options);

  for (int core_size = 1; core_size <= kChunkSize * 5; core_size++) {
    std::string core_contents('0', core_size);
    base::FilePath core = test_dir_.Append("core");
    ASSERT_TRUE(test_util::CreateFile(core, core_contents));

    base::FilePath out = test_dir_.Append("WriteCoredump_ManySizes");
    ASSERT_TRUE(test_util::CreateFile(out, ""));
    serializer.set_output_for_testing(out);

    ASSERT_TRUE(serializer.WriteCoredump(/*crash_id=*/1, core));
    std::string actual;
    ASSERT_TRUE(base::ReadFileToString(out, &actual));

    std::string assembled_core;
    crash::FetchCrashesResponse resp;
    uint64_t pos = 0;
    while (pos < actual.size()) {
      std::string actual_size_str = actual.substr(0, sizeof(uint64_t));
      pos += sizeof(uint64_t);
      uint64_t actual_size;
      base::ReadBigEndian(
          reinterpret_cast<const uint8_t*>(actual_size_str.data()),
          &actual_size);

      resp.ParseFromString(actual.substr(pos, actual_size));
      EXPECT_EQ(resp.crash_id(), 1) << "core size: " << core_size;
      EXPECT_LE(resp.core().size(), kChunkSize) << "core size: " << core_size;
      assembled_core += resp.core();
      pos += actual_size;
    }
    EXPECT_EQ(assembled_core, core_contents) << "core size: " << core_size;
  }
}

TEST_F(CrashSerializerTest, WriteCoredump_Nonexistent) {
  Serializer::Options options;
  Serializer serializer(std::make_unique<test_util::AdvancingClock>(), options);
  EXPECT_FALSE(serializer.WriteCoredump(/*crash_id=*/0,
                                        test_dir_.Append("nonexistent.core")));
}

enum MissingFile {
  kNone,
  kPayloadFile,
  kLogFile,
  kTextFile,
  kBinFile,
  kCoreFile,
};

class CrashSerializerParameterizedTest
    : public CrashSerializerTest,
      public ::testing::WithParamInterface<
          std::tuple<bool, bool, MissingFile>> {
 protected:
  void SetUp() override {
    std::tie(absolute_paths_, fetch_core_, missing_file_) = GetParam();
    CrashSerializerTest::SetUp();
  }
  bool absolute_paths_;
  bool fetch_core_;
  MissingFile missing_file_;
};

TEST_P(CrashSerializerParameterizedTest, SerializeCrash) {
  const base::FilePath system_dir = paths::Get(paths::kSystemCrashDirectory);
  ASSERT_TRUE(base::CreateDirectory(system_dir));

  const base::FilePath payload_file_relative("0.0.0.0.0.payload");
  const base::FilePath payload_file_absolute =
      system_dir.Append(payload_file_relative);
  const std::string payload_contents = "foobar_payload";
  if (missing_file_ != kPayloadFile) {
    ASSERT_TRUE(test_util::CreateFile(payload_file_absolute, payload_contents));
  }
  const base::FilePath& payload_file =
      absolute_paths_ ? payload_file_absolute : payload_file_relative;

  const base::FilePath log_file_relative("0.0.0.0.0.log");
  const base::FilePath log_file_absolute = system_dir.Append(log_file_relative);
  const std::string log_contents = "foobar_log";
  if (missing_file_ != kLogFile) {
    ASSERT_TRUE(test_util::CreateFile(log_file_absolute, log_contents));
  }
  const base::FilePath& log_file =
      absolute_paths_ ? log_file_absolute : log_file_relative;

  const base::FilePath text_var_file_relative("data.txt");
  const base::FilePath text_var_file_absolute =
      system_dir.Append(text_var_file_relative);
  const std::string text_var_contents = "upload_text_contents";
  if (missing_file_ != kTextFile) {
    ASSERT_TRUE(
        test_util::CreateFile(text_var_file_absolute, text_var_contents));
  }
  const base::FilePath& text_var_file =
      absolute_paths_ ? text_var_file_absolute : text_var_file_relative;

  const base::FilePath file_var_file_relative("data.bin");
  const base::FilePath file_var_file_absolute =
      system_dir.Append(file_var_file_relative);
  const std::string file_var_contents = "upload_file_contents";
  if (missing_file_ != kBinFile) {
    ASSERT_TRUE(
        test_util::CreateFile(file_var_file_absolute, file_var_contents));
  }
  const base::FilePath& file_var_file =
      absolute_paths_ ? file_var_file_absolute : file_var_file_relative;

  const base::FilePath core_file_relative("0.0.0.0.0.core");
  const base::FilePath core_file_absolute =
      system_dir.Append(core_file_relative);
  const std::string core_contents = "corey_mccoreface";
  if (missing_file_ != kCoreFile) {
    ASSERT_TRUE(test_util::CreateFile(core_file_absolute, core_contents));
  }

  brillo::KeyValueStore metadata;
  metadata.SetString("exec_name", "fake_exec_name");
  metadata.SetString("ver", "fake_chromeos_ver");
  metadata.SetString("upload_var_prod", "fake_product");
  metadata.SetString("upload_var_ver", "fake_version");
  metadata.SetString("sig", "fake_sig");
  metadata.SetString("upload_var_guid", "SHOULD_NOT_BE_USED");
  metadata.SetString("upload_var_foovar", "bar");
  metadata.SetString("upload_var_in_progress_integration_test", "test.Test");
  metadata.SetString("upload_var_collector", "fake_collector");
  metadata.SetString("upload_text_footext", text_var_file.value());
  metadata.SetString("upload_file_log", log_file.value());
  metadata.SetString("upload_file_foofile", file_var_file.value());
  metadata.SetString("error_type", "fake_error");

  util::CrashDetails details = {
      .meta_file = base::FilePath(system_dir).Append("0.0.0.0.0.meta"),
      .payload_file = payload_file,
      .payload_kind = "fake_payload",
      .client_id = kFakeClientId,
      .metadata = metadata,
  };

  Serializer::Options options;
  options.fetch_coredumps = fetch_core_;

  Serializer serializer(std::make_unique<test_util::AdvancingClock>(), options);

  crash::CrashInfo info;
  std::vector<crash::CrashBlob> blobs;
  base::FilePath core_path;
  EXPECT_EQ(serializer.SerializeCrash(details, &info, &blobs, &core_path),
            missing_file_ != kPayloadFile);

  if (missing_file_ == kPayloadFile) {
    return;
  }

  // We'd really like to set up a proto with the expected values and
  // EXPECT_THAT(info, EqualsProto(expected_info)), but EqualsProto is
  // unavailable in chromium OS, so do it one field at a time instead.
  EXPECT_EQ(info.exec_name(), "fake_exec_name");
  EXPECT_EQ(info.prod(), "fake_product");
  EXPECT_EQ(info.ver(), "fake_version");
  EXPECT_EQ(info.sig(), "fake_sig");
  EXPECT_EQ(info.in_progress_integration_test(), "test.Test");
  EXPECT_EQ(info.collector(), "fake_collector");

  int num_fields = 8;
  // Absolute paths are masked
  if (!absolute_paths_ && missing_file_ != kTextFile) {
    num_fields++;  // No missing text file
  }
  if (absolute_paths_) {
    num_fields += 3;  // Account for the 3 blocked files
  }

  ASSERT_EQ(info.fields_size(), num_fields);

  int field_idx = 0;
  EXPECT_EQ(info.fields(field_idx).key(), "board");
  EXPECT_EQ(info.fields(field_idx).text(), "undefined");
  field_idx++;

  EXPECT_EQ(info.fields(field_idx).key(), "hwclass");
  EXPECT_EQ(info.fields(field_idx).text(), "undefined");
  field_idx++;

  EXPECT_EQ(info.fields(field_idx).key(), "sig2");
  EXPECT_EQ(info.fields(field_idx).text(), "fake_sig");
  field_idx++;

  EXPECT_EQ(info.fields(field_idx).key(), "image_type");
  EXPECT_EQ(info.fields(field_idx).text(), "");
  field_idx++;

  EXPECT_EQ(info.fields(field_idx).key(), "boot_mode");
  EXPECT_EQ(info.fields(field_idx).text(), "missing-crossystem");
  field_idx++;

  EXPECT_EQ(info.fields(field_idx).key(), "error_type");
  EXPECT_EQ(info.fields(field_idx).text(), "fake_error");
  field_idx++;

  EXPECT_EQ(info.fields(field_idx).key(), "guid");
  EXPECT_EQ(info.fields(field_idx).text(), "00112233445566778899aabbccddeeff");
  field_idx++;

  if (!absolute_paths_ && missing_file_ != kTextFile) {
    EXPECT_EQ(info.fields(field_idx).key(), "footext");
    EXPECT_EQ(info.fields(field_idx).text(), "upload_text_contents");
    field_idx++;
  }

  if (absolute_paths_) {
    EXPECT_EQ(info.fields(field_idx).key(), "file_blocked_by_path");
    EXPECT_EQ(info.fields(field_idx).text(), file_var_file.value());
  } else {
    EXPECT_EQ(info.fields(field_idx).key(), "foovar");
    EXPECT_EQ(info.fields(field_idx).text(), "bar");
  }
  field_idx++;

  int num_blobs = 1;
  if (!absolute_paths_ && missing_file_ != kBinFile) {
    num_blobs++;
  }
  if (!absolute_paths_ && missing_file_ != kLogFile) {
    num_blobs++;
  }

  ASSERT_EQ(blobs.size(), num_blobs);

  int blob_idx = 0;
  if (!absolute_paths_) {
    EXPECT_EQ(blobs[blob_idx].key(), "upload_file_fake_payload");
    EXPECT_EQ(blobs[blob_idx].blob(), "foobar_payload");
    EXPECT_EQ(blobs[blob_idx].filename(), payload_file_relative.value());
    blob_idx++;
  }

  if (!absolute_paths_ && missing_file_ != kBinFile) {
    EXPECT_EQ(blobs[blob_idx].key(), "foofile");
    EXPECT_EQ(blobs[blob_idx].blob(), "upload_file_contents");
    EXPECT_EQ(blobs[blob_idx].filename(), file_var_file_relative.value());
    blob_idx++;
  }

  if (!absolute_paths_ && missing_file_ != kLogFile) {
    EXPECT_EQ(blobs[blob_idx].key(), "log");
    EXPECT_EQ(blobs[blob_idx].blob(), "foobar_log");
    EXPECT_EQ(blobs[blob_idx].filename(), log_file_relative.value());
    blob_idx++;
  }

  if (missing_file_ != kCoreFile && fetch_core_) {
    EXPECT_EQ(core_path, core_file_absolute);
  } else {
    EXPECT_EQ(core_path, base::FilePath());
  }
}

INSTANTIATE_TEST_SUITE_P(CrashSerializerParameterizedTestInstantiation,
                         CrashSerializerParameterizedTest,
                         testing::Combine(testing::Bool(),
                                          testing::Bool(),
                                          testing::Values(kNone,
                                                          kPayloadFile,
                                                          kLogFile,
                                                          kTextFile,
                                                          kBinFile,
                                                          kCoreFile)));

}  // namespace crash_serializer
