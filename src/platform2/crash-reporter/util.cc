// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/util.h"

#include <poll.h>
#include <signal.h>
#include <stdlib.h>

#include <algorithm>
#include <map>
#include <memory>

#include <base/check_op.h>
#include <base/logging.h>

#if USE_DIRENCRYPTION
#include <keyutils.h>
#endif  // USE_DIRENCRYPTION

#include <base/command_line.h>
#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/json/json_reader.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/values.h>
#include <brillo/cryptohome.h>
#include <brillo/key_value_store.h>
#include <brillo/userdb_utils.h>
#include <re2/re2.h>
#include <zlib.h>

#include "crash-reporter/crossystem.h"
#include "crash-reporter/paths.h"
#include "crash-reporter/vm_support.h"

namespace util {

namespace {

constexpr size_t kBufferSize = 4096;

// Path to hardware class description.
constexpr char kHwClassPath[] = "/sys/devices/platform/chromeos_acpi/HWID";

constexpr char kDevSwBoot[] = "devsw_boot";
constexpr char kDevMode[] = "dev";

// If the OS version is older than this we do not upload crash reports.
constexpr base::TimeDelta kAgeForNoUploads = base::Days(180);

#if USE_DIRENCRYPTION
// Name of the session keyring.
const char kDircrypt[] = "dircrypt";
#endif  // USE_DIRENCRYPTION

}  // namespace

const int kDefaultMaxUploadBytes = 1024 * 1024;

bool IsCrashTestInProgress() {
  return base::PathExists(paths::GetAt(paths::kSystemRunStateDirectory,
                                       paths::kCrashTestInProgress));
}

bool IsDeviceCoredumpUploadAllowed() {
  return base::PathExists(paths::GetAt(paths::kCrashReporterStateDirectory,
                                       paths::kDeviceCoredumpUploadAllowed));
}

bool IsDeveloperImage() {
  // If we're testing crash reporter itself, we don't want to special-case
  // for developer images.
  if (IsCrashTestInProgress())
    return false;
  return base::PathExists(paths::Get(paths::kLeaveCoreFile));
}

// Determines if this is a test image, IGNORING IsCrashTestInProgress.
// Use sparingly, and only if you're really sure you want to have different
// behavior during crash tests than on real devices.
bool IsReallyTestImage() {
  std::string channel;
  if (!GetCachedKeyValueDefault(base::FilePath(paths::kLsbRelease),
                                "CHROMEOS_RELEASE_TRACK", &channel)) {
    return false;
  }
  return base::StartsWith(channel, "test", base::CompareCase::SENSITIVE);
}

bool IsTestImage() {
  // If we're testing crash reporter itself, we don't want to special-case
  // for test images.
  if (IsCrashTestInProgress())
    return false;

  return IsReallyTestImage();
}

bool IsOfficialImage() {
  std::string description;
  if (!GetCachedKeyValueDefault(base::FilePath(paths::kLsbRelease),
                                "CHROMEOS_RELEASE_DESCRIPTION", &description)) {
    return false;
  }

  return description.find("Official") != std::string::npos;
}

bool HasMockConsent() {
  // Don't bypass user consent on real Chromebooks; this is for testing.
  // We can't use IsTestImage because that's always false if a crash test is in
  // progress.
  if (!IsReallyTestImage()) {
    return false;
  }
  return base::PathExists(
      paths::GetAt(paths::kSystemRunStateDirectory, paths::kMockConsent));
}

bool UseLooseCoreSizeForChromeCrashEarly() {
  return util::IsReallyTestImage() &&
         base::PathExists(
             paths::GetAt(paths::kSystemRunStateDirectory,
                          paths::kRunningLooseChromeCrashEarlyTestFile));
}

bool IsFeedbackAllowed(MetricsLibraryInterface* metrics_lib) {
  if (HasMockConsent()) {
    LOG(INFO) << "mock-consent file present; assuming consent";
    return true;
  }
  // For developer builds, we always want to keep the crash reports unless
  // we're testing the crash facilities themselves.  This overrides
  // feedback.  Crash sending still obeys consent.
  if (IsDeveloperImage()) {
    LOG(INFO) << "developer build - not testing - always dumping";
    return true;
  }

  VmSupport* vm_support = VmSupport::Get();
  bool ret = false;
  if (vm_support) {
    ret = vm_support->GetMetricsConsent();
  } else {
    ret = metrics_lib->AreMetricsEnabled();
  }

  if (!ret) {
    LOG(WARNING)
        << "No consent. Not handling invocation: "
        << base::CommandLine::ForCurrentProcess()->GetCommandLineString();
  }

  return ret;
}

bool IsBootFeedbackAllowed(MetricsLibraryInterface* metrics_lib) {
  std::string contents;
  if (base::ReadFileToString(paths::Get(paths::kBootConsentFile), &contents)) {
    if (contents != "1") {
      return false;
    }
    // else fall back to normal consent -- checking policy, etc., as
    // metrics_library does.
  }
  return IsFeedbackAllowed(metrics_lib);
}

// Determine if the filter-in file tells us to skip
static bool SkipForFilterIn(std::string command_line) {
  base::FilePath file =
      paths::GetAt(paths::kSystemRunStateDirectory, paths::kFilterInFile);
  if (!base::PathExists(file)) {
    return false;
  }

  std::string contents;
  if (!base::ReadFileToString(file, &contents)) {
    LOG(WARNING) << "Failed to read " << file;
    return false;
  }

  if (contents == "none" || command_line.find(contents) == std::string::npos) {
    // Doesn't match, so skip this crash.
    LOG(WARNING) << "Ignoring crash invocation '" << command_line << "' due to "
                 << "filter_in=" << contents << ".";
    return true;
  }
  return false;
}

// Determine if the filter-out file tells us to skip
static bool SkipForFilterOut(std::string command_line) {
  base::FilePath file =
      paths::GetAt(paths::kSystemRunStateDirectory, paths::kFilterOutFile);
  if (!base::PathExists(file)) {
    return false;
  }

  std::string contents;
  if (!base::ReadFileToString(file, &contents)) {
    LOG(WARNING) << "Failed to read " << file;
    return false;
  }

  if (command_line.find(contents) != std::string::npos) {
    // Matches, so skip this crash.
    LOG(WARNING) << "Ignoring crash invocation '" << command_line << "' due to "
                 << "filter_out=" << contents << ".";
    return true;
  }
  return false;
}

bool SkipCrashCollection(int argc, const char* const argv[]) {
  // Don't skip crashes on real Chromebooks; this is for testing.
  // We can't use IsTestImage because that's always false if a crash test is in
  // progress.
  if (!IsReallyTestImage()) {
    return false;
  }

  std::vector<std::string> args(argv + 1, argv + argc);
  std::string command_line = base::JoinString(args, " ");

  // If the command line consists solely of these flags, it's always allowed
  // (regardless of filter-in state).
  // These flags are always accepted because they do not create crash files.
  // Tests may wish to verify or depend on their effects while also blocking all
  // crashes (using a filter-in of "none").
  const std::vector<std::string> allowlist = {
      "--init",
      "--clean_shutdown",
      "--log_to_stderr",
  };

  bool all_args_allowed = true;
  for (auto it = args.begin(); it != args.end() && all_args_allowed; ++it) {
    if (std::find(allowlist.begin(), allowlist.end(), *it) == allowlist.end()) {
      all_args_allowed = false;
    }
  }
  if (all_args_allowed) {
    return false;
  }

  return SkipForFilterIn(command_line) || SkipForFilterOut(command_line);
}

bool SetGroupAndPermissions(const base::FilePath& file,
                            const char* group,
                            bool execute) {
  gid_t gid;
  if (!brillo::userdb::GetGroupInfo(group, &gid)) {
    LOG(ERROR) << "Couldn't look up group " << group;
    return false;
  }
  if (lchown(file.value().c_str(), -1, gid) != 0) {
    PLOG(ERROR) << "Couldn't chown " << file.value();
    return false;
  }
  int mode;
  if (!base::GetPosixFilePermissions(file, &mode)) {
    PLOG(ERROR) << "Couldn't get file permissions for " << file.value();
    return false;
  }
  mode_t group_mode = S_IRGRP | S_IWGRP;
  if (execute) {
    group_mode |= S_IXGRP;
  }
  if (!base::SetPosixFilePermissions(file, mode | group_mode)) {
    PLOG(ERROR) << "Couldn't chmod " << file.value();
    return false;
  }
  return true;
}

base::Time GetOsTimestamp() {
  base::FilePath lsb_release_path =
      paths::Get(paths::kEtcDirectory).Append(paths::kLsbRelease);
  base::File::Info info;
  if (!base::GetFileInfo(lsb_release_path, &info)) {
    LOG(ERROR) << "Failed reading info for /etc/lsb-release";
    return base::Time();
  }

  return info.last_modified;
}

bool IsBuildTimestampTooOldForUploads(int64_t build_time_millis,
                                      base::Clock* clock) {
  if (build_time_millis == 0) {
    return true;
  } else if (build_time_millis < 0) {
    LOG(ERROR) << "build timestamp is negative: " << build_time_millis;
    return false;
  }
  base::Time timestamp(base::Time::UnixEpoch() +
                       base::Milliseconds(build_time_millis));
  if (timestamp.is_null()) {
    return false;
  }
  base::Time now = clock->Now();
  // In case of invalid timestamps, always upload a crash -- something strange
  // is happening.
  if (timestamp > now) {
    LOG(ERROR) << "OS timestamp is in the future: " << timestamp;
    return false;
  } else if (timestamp < base::Time::UnixEpoch()) {
    LOG(ERROR) << "OS timestamp is negative: " << timestamp;
    return false;
  }
  return (now - timestamp) > kAgeForNoUploads;
}

std::string GetHardwareClass() {
  std::string hw_class;
  if (base::ReadFileToString(paths::Get(kHwClassPath), &hw_class))
    return hw_class;
  auto vb_value = crossystem::GetInstance()->VbGetSystemPropertyString("hwid");
  return vb_value ? vb_value.value() : "undefined";
}

std::string GetBootModeString() {
  // If we're testing crash reporter itself, we don't want to special-case
  // for developer mode.
  if (IsCrashTestInProgress())
    return "";

  auto vb_value = crossystem::GetInstance()->VbGetSystemPropertyInt(kDevSwBoot);
  if (!vb_value) {
    LOG(ERROR) << "Error trying to determine boot mode";
    return "missing-crossystem";
  }
  if (vb_value.value() == 1)
    return kDevMode;

  return "";
}

bool GetCachedKeyValue(const base::FilePath& base_name,
                       const std::string& key,
                       const std::vector<base::FilePath>& directories,
                       std::string* value) {
  std::vector<std::string> error_reasons;
  for (const auto& directory : directories) {
    const base::FilePath file_name = directory.Append(base_name);
    if (!base::PathExists(file_name)) {
      error_reasons.push_back(file_name.value() + " not found");
      continue;
    }
    brillo::KeyValueStore store;
    if (!store.Load(file_name)) {
      LOG(WARNING) << "Problem parsing " << file_name.value();
      // Even though there was some failure, take as much as we could read.
    }
    if (!store.GetString(key, value)) {
      error_reasons.push_back("Key not found in " + file_name.value());
      continue;
    }
    return true;
  }
  LOG(WARNING) << "Unable to find " << key << ": "
               << base::JoinString(error_reasons, ", ");
  return false;
}

bool GetCachedKeyValueDefault(const base::FilePath& base_name,
                              const std::string& key,
                              std::string* value) {
  const std::vector<base::FilePath> kDirectories = {
      paths::Get(paths::kCrashReporterStateDirectory),
      paths::Get(paths::kEtcDirectory),
  };
  return GetCachedKeyValue(base_name, key, kDirectories, value);
}

bool GetUserHomeDirectories(
    org::chromium::SessionManagerInterfaceProxyInterface* session_manager_proxy,
    std::vector<base::FilePath>* directories) {
  brillo::ErrorPtr error;
  std::map<std::string, std::string> sessions;
  session_manager_proxy->RetrieveActiveSessions(&sessions, &error);

  if (error) {
    LOG(ERROR) << "Error calling D-Bus proxy call to interface "
               << "'" << session_manager_proxy->GetObjectPath().value()
               << "': " << error->GetMessage();
    return false;
  }

  for (const auto& iter : sessions) {
    brillo::cryptohome::home::ObfuscatedUsername username(iter.second);
    directories->push_back(paths::Get(
        brillo::cryptohome::home::GetHashedUserPath(username).value()));
  }

  return true;
}

bool GetUserCrashDirectories(
    org::chromium::SessionManagerInterfaceProxyInterface* session_manager_proxy,
    std::vector<base::FilePath>* directories) {
  std::vector<base::FilePath> home_directories;
  if (!GetUserHomeDirectories(session_manager_proxy, &home_directories)) {
    return false;
  }

  for (const auto& iter : home_directories) {
    directories->push_back(iter.Append("crash"));
  }

  return true;
}

bool GetDaemonStoreCrashDirectories(
    org::chromium::SessionManagerInterfaceProxyInterface* session_manager_proxy,
    std::vector<base::FilePath>* directories) {
  if (!session_manager_proxy) {
    LOG(ERROR) << "Can't get active sessions - no session manager proxy";
    return false;
  }
  brillo::ErrorPtr error;
  std::map<std::string, std::string> sessions;
  session_manager_proxy->RetrieveActiveSessions(&sessions, &error);

  if (error) {
    LOG(ERROR) << "Error calling D-Bus proxy call to interface "
               << "'" << session_manager_proxy->GetObjectPath().value()
               << "': " << error->GetMessage();
    return false;
  }

  for (const auto& iter : sessions) {
    directories->push_back(
        paths::Get(base::FilePath(paths::kCryptohomeCrashDirectory)
                       .Append(iter.second)
                       .value()));
  }

  return true;
}

std::vector<unsigned char> GzipStream(brillo::StreamPtr data) {
  // Adapted from https://zlib.net/zlib_how.html
  z_stream deflate_stream;
  memset(&deflate_stream, 0, sizeof(deflate_stream));
  deflate_stream.zalloc = Z_NULL;
  deflate_stream.zfree = Z_NULL;

  // Using a window size of 31 sets us to gzip mode (16) + default window size
  // (15).
  const int kDefaultWindowSize = 15;
  const int kWindowSizeGzipAdd = 16;
  const int kDefaultMemLevel = 8;
  int result = deflateInit2(&deflate_stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                            kDefaultWindowSize + kWindowSizeGzipAdd,
                            kDefaultMemLevel, Z_DEFAULT_STRATEGY);
  if (result != Z_OK) {
    LOG(ERROR) << "Error initializing zlib: error code " << result
               << ", error msg: "
               << (deflate_stream.msg == nullptr ? "None" : deflate_stream.msg);
    return std::vector<unsigned char>();
  }

  std::vector<unsigned char> deflated;
  int flush = Z_NO_FLUSH;
  /* compress until end of stream */
  do {
    size_t read_size = 0;
    unsigned char in[kBufferSize];
    if (!data->ReadBlocking(in, kBufferSize, &read_size, nullptr)) {
      // We are reading from a memory stream, so this really shouldn't happen.
      LOG(ERROR) << "Error reading from input stream";
      deflateEnd(&deflate_stream);
      return std::vector<unsigned char>();
    }
    if (data->GetRemainingSize() <= 0) {
      // We must request a flush on the last chunk of data, else deflateEnd
      // may just discard some compressed data.
      flush = Z_FINISH;
    }
    deflate_stream.next_in = in;
    deflate_stream.avail_in = read_size;
    do {
      unsigned char out[kBufferSize];
      deflate_stream.avail_out = kBufferSize;
      deflate_stream.next_out = out;
      result = deflate(&deflate_stream, flush);
      // Note that most return values are acceptable; don't error out if result
      // is not Z_OK. See discussion at https://zlib.net/zlib_how.html
      DCHECK_NE(result, Z_STREAM_ERROR);
      DCHECK_LE(deflate_stream.avail_out, kBufferSize);
      int amount_in_output_buffer = kBufferSize - deflate_stream.avail_out;
      deflated.insert(deflated.end(), out, out + amount_in_output_buffer);
    } while (deflate_stream.avail_out == 0);
    DCHECK_EQ(deflate_stream.avail_in, 0) << "deflate did not consume all data";
  } while (flush != Z_FINISH);
  DCHECK_EQ(result, Z_STREAM_END) << "Stream did not complete properly";
  deflateEnd(&deflate_stream);
  return deflated;
}

int RunAndCaptureOutput(brillo::ProcessImpl* process,
                        int fd,
                        std::string* output) {
  process->RedirectUsingPipe(fd, false);
  if (process->Start()) {
    const int out = process->GetPipe(fd);
    char buffer[kBufferSize];
    output->clear();

    while (true) {
      const ssize_t count = HANDLE_EINTR(read(out, buffer, kBufferSize));
      if (count < 0) {
        process->Wait();
        break;
      }

      if (count == 0)
        return process->Wait();

      output->append(buffer, count);
    }
  }

  return -1;
}

void LogMultilineError(const std::string& error) {
  std::vector<base::StringPiece> lines = base::SplitStringPiece(
      error, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  for (auto line : lines)
    LOG(ERROR) << line;
}

bool ReadMemfdToString(int mem_fd, std::string* contents) {
  if (contents)
    contents->clear();
  base::ScopedFILE file(fdopen(mem_fd, "r"));
  if (!file) {
    PLOG(ERROR) << "Failed to fdopen(" << mem_fd << ")";
    return false;
  }
  if (fseeko(file.get(), 0, SEEK_END) != 0) {
    PLOG(ERROR) << "fseeko() error";
    return false;
  }
  off_t file_size = ftello(file.get());
  if (file_size < 0) {
    PLOG(ERROR) << "ftello() error";
    return false;
  } else if (file_size == 0) {
    LOG(ERROR) << "Minidump memfd has size of 0";
    return false;
  }

  if (fseeko(file.get(), 0, SEEK_SET) != 0) {
    PLOG(ERROR) << "fseeko() error";
    return false;
  }

  std::unique_ptr<char[]> buf(new char[file_size]);
  if (fread(buf.get(), 1, file_size, file.get()) != file_size) {
    PLOG(ERROR) << "fread() error";
    return false;
  }
  if (contents)
    contents->assign(buf.get(), file_size);

  return true;
}

int GetSelinuxWeight() {
  return 100'000;
}

int GetSelinuxWeightForCrash() {
  // For consistency, and to avoid a sudden change in the apparent number of
  // selinux violations, weight them to be 1000x fewer when reporting to crash
  // (see util.h).
  return GetSelinuxWeight() / 1000;
}

int GetServiceFailureWeight() {
  return 1000;
}

int GetSuspendFailureWeight() {
  return 50;
}

int GetOomEventWeight() {
  return 10;
}

int GetKernelWarningWeight(const std::string& flag) {
  // Sample kernel wifi warnings at a higher weight, since they're heavily
  // environmentally influenced.
  // Sample iwlwifi errors and ath10k errors using a higher weight since they're
  // not as useful and are only actionable for WiFi vendors.
  if (flag == "--kernel_wifi_warning" || flag == "--kernel_ath10k_error" ||
      flag == "--kernel_iwlwifi_error") {
    return 50;
  } else if (flag == "--kernel_warning" || flag == "--kernel_suspend_warning") {
    return 10;
  } else {
    return 1;  // e.g. kernel_smmu_fault
  }
}

int GetUmountStatefulFailureWeight() {
  return 10;
}

int GetRecoveryFailureWeight() {
  return 10;
}

bool ReadFdToStream(unsigned int fd, std::stringstream* stream) {
  base::File src(fd);
  char buffer[kBufferSize];

  while (true) {
    const int count = src.ReadAtCurrentPosNoBestEffort(buffer, kBufferSize);
    if (count < 0)
      return false;

    if (count == 0)
      return stream->tellp() > 0;  // Crash log should not be empty.

    stream->write(buffer, count);
  }
}

int GetNextLine(base::File& file, std::string& out_str) {
  char ch;

  out_str.clear();
  while (file.ReadAtCurrentPos(&ch, sizeof(ch)) > 0 && ch != '\n') {
    out_str.push_back(ch);
  }

  return out_str.size();
}

#if USE_DIRENCRYPTION
void JoinSessionKeyring() {
  key_serial_t session_keyring = keyctl_join_session_keyring(kDircrypt);
  if (session_keyring == -1) {
    // The session keyring may not exist if ext4 encryption isn't enabled so
    // just log an info message instead of an error.
    PLOG(INFO) << "Unable to join session keying";
  }
}
#endif  // USE_DIRENCRYPTION

// Hash a string to a number.  We define our own hash function to not
// be dependent on a C++ library that might change.  This function
// uses basically the same approach as tr1/functional_hash.h but with
// a larger prime number (16127 vs 131).
unsigned HashString(base::StringPiece input) {
  unsigned hash = 0;
  for (auto c : input)
    hash = hash * 16127 + c;
  return hash;
}

base::FilePath GetPathToThisBinary(const char* const argv[]) {
  // To support usage with lddtree, allow overriding argv[0] with the LD_ARGV0
  // environment variable set by lddtree wrappers. Without this, core_pattern
  // will include a .elf suffix, bypassing the lddtree wrapper, leaving
  // crash_reporter unable to start in response to crashes.
  //
  // TODO(crbug.com/1003841): Remove LD_ARGV0 once ld.so supports forwarding
  // the binary name.
  const char* arg0 = getenv("LD_ARGV0");
  if (arg0 == nullptr || arg0[0] == '\0') {
    arg0 = argv[0];
  }
  return base::MakeAbsoluteFilePath(base::FilePath(arg0));
}

bool RedactDigests(std::string* to_filter) {
  static constexpr const LazyRE2 digest_re = {
      R"((^|[^0-9a-fA-F])(?:[0-9a-fA-F]{32,})([^0-9a-fA-F]|$))"};
  return re2::RE2::Replace(to_filter, *digest_re, R"(\1<Redacted Digest>\2)");
}

std::optional<std::string> ExtractChromeVersionFromMetadata(
    const base::FilePath& metadata_path) {
  // Arbitrary max, just for safety. The json file should be under a kilobyte.
  constexpr size_t kMaxSize = 128 * 1024;
  std::string raw_metadata;
  if (!ReadFileToStringWithMaxSize(metadata_path, &raw_metadata, kMaxSize)) {
    PLOG(ERROR) << "Could not read Chrome metadata file "
                << metadata_path.value() << ": ";
    return std::nullopt;
  }

  auto parsed_metadata =
      base::JSONReader::ReadAndReturnValueWithError(raw_metadata);

  if (!parsed_metadata.has_value()) {
    LOG(ERROR) << "Error parsing Chrome metadata file " << metadata_path.value()
               << " as JSON: " << parsed_metadata.error().message;
    return std::nullopt;
  }

  if (!parsed_metadata->is_dict()) {
    LOG(ERROR) << "Error parsing Chrome metadata file " << metadata_path.value()
               << ": expected outermost value to be a DICTIONARY but got a "
               << base::Value::GetTypeName(parsed_metadata->type());
    return std::nullopt;
  }

  const base::Value* content = parsed_metadata->GetDict().Find("content");
  if (content == nullptr) {
    LOG(ERROR) << "Error parsing Chrome metadata file " << metadata_path.value()
               << ": could not find 'content' key";
    return std::nullopt;
  }
  if (!content->is_dict()) {
    LOG(ERROR) << "Error parsing Chrome metadata file " << metadata_path.value()
               << ": content is not a DICT but instead a "
               << base::Value::GetTypeName(content->type());
    return std::nullopt;
  }
  const base::Value* version = content->GetDict().Find("version");
  if (version == nullptr) {
    LOG(ERROR) << "Error parsing Chrome metadata file " << metadata_path.value()
               << ": could not find 'version' key";
    return std::nullopt;
  }

  const std::string* version_string = version->GetIfString();
  if (version_string == nullptr) {
    LOG(ERROR) << "Error parsing Chrome metadata file " << metadata_path.value()
               << ": version is not a string but instead a "
               << base::Value::GetTypeName(version->type());
    return std::nullopt;
  }

  return *version_string;
}

}  // namespace util
