// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/chrome_collector.h"

#include <stdint.h>
#include <string.h>

#include <limits>
#include <map>
#include <string>

#include <base/barrier_closure.h>
#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/run_loop.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <brillo/data_encoding.h>
#include <brillo/process/process.h>
#include <brillo/syslog_logging.h>
#include <brillo/variant_dictionary.h>
#include <re2/re2.h>

#include "crash-reporter/constants.h"
#include "crash-reporter/util.h"

using base::FilePath;

namespace {

constexpr char kDefaultMinidumpName[] = "upload_file_minidump";
constexpr char kDefaultJavaScriptStackName[] = "upload_file_js_stack";

// Filenames for logs attached to crash reports. Also used as metadata keys.
constexpr char kChromeLogFilename[] = "chrome.txt";
constexpr char kGpuStateFilename[] = "i915_error_state.log.xz";
constexpr char kDmesgOutputFilename[] = "dmesg.txt";

// Filename for the pid of the browser process if it was aborted due to a
// browser hang. Written by session_manager.
constexpr char kAbortedBrowserPidPath[] = "/run/chrome/aborted_browser_pid";

// Filename for the pid of the browser process if it was aborted due to a
// slow shutdown. Written by session_manager.
const char kShutdownBrowserPidPath[] = "/run/chrome/shutdown_browser_pid";

// Whenever we have an executable crash, we use this key for the logging config
// file. See HandleCrashWithDumpData for explanation.
constexpr char kExecLogKeyName[] = "chrome";

// When the executable is a lacros-chrome instance, use this key instead.
constexpr char kLacrosChromeLogKeyName[] = "lacros_chrome";

// Extract a string delimited by the given character, from the given offset
// into a source string. Returns false if the string is zero-sized or no
// delimiter was found.
bool GetDelimitedString(const std::string& str,
                        char ch,
                        size_t offset,
                        std::string* substr) {
  size_t at = str.find_first_of(ch, offset);
  if (at == std::string::npos || at == offset || at == str.length() - 1)
    return false;
  *substr = str.substr(offset, at - offset);
  return true;
}

}  // namespace

ChromeCollector::ChromeCollector(CrashSendingMode crash_sending_mode)
    : CrashCollector("chrome",
                     kUseNormalCrashDirectorySelectionMethod,
                     crash_sending_mode),
      output_file_ptr_(stdout),
      max_upload_bytes_(util::kDefaultMaxUploadBytes) {}

ChromeCollector::~ChromeCollector() {}

bool ChromeCollector::HandleCrashWithDumpData(
    const std::string& data,
    pid_t pid,
    uid_t uid,
    const std::string& executable_name,
    const std::string& non_exe_error_key,
    const std::string& dump_dir,
    int signal) {
  // Perform basic input validation.
  CHECK(pid >= (pid_t)0) << "--pid= must be set";
  CHECK(uid >= (uid_t)0) << "--uid= must be set";
  CHECK_NE(executable_name.empty(), non_exe_error_key.empty())
      << "Exactly one of --exe= and --error_key= must be set";
  CHECK(dump_dir.empty() || util::IsTestImage())
      << "--chrome_dump_dir is only for tests";

  const CrashType crash_type =
      executable_name.empty() ? kJavaScriptError : kExecutableCrash;

  const std::string& key_for_basename =
      (crash_type == kExecutableCrash) ? executable_name : non_exe_error_key;
  // anomaly_detector's CrashReporterParser looks for this message; don't change
  // it without updating the regex.
  LOG(WARNING) << "Received crash notification for " << key_for_basename << "["
               << pid << "] user " << uid << " (called directly)";

  if (key_for_basename.find('/') != std::string::npos) {
    LOG(ERROR) << "--exe or --error_key contains illegal characters: "
               << key_for_basename;
    return false;
  }

  FilePath dir;
  if (!dump_dir.empty()) {
    dir = FilePath(dump_dir);
  } else if (!GetCreatedCrashDirectoryByEuid(uid, &dir, nullptr)) {
    LOG(ERROR) << "Can't create crash directory for uid " << uid;
    return false;
  }

  std::string dump_basename =
      FormatDumpBasename(key_for_basename, time(nullptr), pid);
  bool is_lacros_crash = false;
  FilePath meta_path = GetCrashPath(dir, dump_basename, "meta");
  FilePath payload_path;
  if (!ParseCrashLog(data, dir, dump_basename, crash_type, &payload_path,
                     &is_lacros_crash)) {
    LOG(ERROR) << "Failed to parse Chrome's crash log";
    return false;
  }

  // TODO(b/269159625): Use signal_, crash_type_, is_lacros_crash_, and
  // shutdown-type to determine crash severity.
  signal_ = signal;
  is_lacros_crash_ = is_lacros_crash;
  crash_type_ = crash_type;

  if (payload_path.empty()) {
    if (crash_type == kJavaScriptError) {
      // This is expected. Some classes of JavaScript errors don't have a stack
      // (specifically unhandled promise rejections). Since crash_sender will
      // not send without a payload, make a "No stack" payload.
      if (!CreateNoStackJSPayload(dir, dump_basename, &payload_path)) {
        return false;
      }
    } else {
      LOG(ERROR) << "Did not get a payload";
      return false;
    }
  }

  // Keyed by crash metadata key name.
  // For Chrome crashes, we need to know if we're in lacros, as the paths used
  // for logs are different (/home/chronos/user/lacros/lacros.log).
  // For non-lacros crashes, we always use the logging key "chrome".
  // We may get names like "unknown" if the process disappeared before Breakpad
  // Crashpad could retrieve the executable name. It's probably chrome, so get
  // the normal chrome logs.
  // Non-lacros JavaScript crashes with their non-exe error keys have different
  // logs. For example, there's no point in getting session_manager logs for a
  // JavaScript crash.
  std::string key_for_logs;
  if (is_lacros_crash) {
    key_for_logs = std::string(kLacrosChromeLogKeyName);
  } else if (crash_type == kExecutableCrash) {
    key_for_logs = std::string(kExecLogKeyName);
  } else {
    key_for_logs = non_exe_error_key;
  }

  const std::map<std::string, base::FilePath> additional_logs =
      GetAdditionalLogs(dir, dump_basename, key_for_logs, crash_type);
  for (const auto& it : additional_logs) {
    VLOG(1) << "Adding metadata: " << it.first << " -> " << it.second.value();
    // Call AddCrashMetaUploadFile() rather than AddCrashMetaData() here. The
    // former adds a prefix to the key name; without the prefix, only the key
    // "logs" appears to be displayed on the crash server.
    AddCrashMetaUploadFile(it.first, it.second.BaseName().value());
  }

  base::FilePath aborted_path(kAbortedBrowserPidPath);
  std::string pid_data;
  if (base::ReadFileToString(aborted_path, &pid_data)) {
    base::TrimWhitespaceASCII(pid_data, base::TRIM_TRAILING, &pid_data);
    if (pid_data == base::NumberToString(pid)) {
      AddCrashMetaUploadData("browser_hang", "true");
      base::DeleteFile(aborted_path);
    }
  }

  base::FilePath shutdown_path(kShutdownBrowserPidPath);
  if (base::ReadFileToString(shutdown_path, &pid_data)) {
    base::TrimWhitespaceASCII(pid_data, base::TRIM_TRAILING, &pid_data);
    if (pid_data == base::NumberToString(pid)) {
      AddCrashMetaUploadData("browser_shutdown_hang", "true");
      base::DeleteFile(shutdown_path);
    }
  }

  // We're done. Note that if we got --error_key, we don't upload an exec_name
  // field to the server.
  FinishCrash(meta_path, executable_name, payload_path.BaseName().value());

  // In production |output_file_ptr_| must be stdout because chrome expects to
  // read the magic string there.
  fprintf(output_file_ptr_, "%s", kSuccessMagic);
  fflush(output_file_ptr_);

  return true;
}

bool ChromeCollector::CreateNoStackJSPayload(const base::FilePath& dir,
                                             const std::string& dump_basename,
                                             base::FilePath* payload_path) {
  *payload_path =
      GetCrashPath(dir, dump_basename, constants::kJavaScriptStackExtension);
  constexpr char kNoStackPayload[] = "No Stack\n";
  if (WriteNewFile(*payload_path, kNoStackPayload) != strlen(kNoStackPayload)) {
    // Can't send a crash report without a payload, so just fail.
    LOG(ERROR) << "Failed to write lack-of-js-stack message to "
               << payload_path->value();
    return false;
  }
  return true;
}

bool ChromeCollector::HandleCrash(const FilePath& dump_file_path,
                                  pid_t pid,
                                  uid_t uid,
                                  const std::string& exe_name,
                                  int signal) {
  std::string data;
  if (!base::ReadFileToString(base::FilePath(dump_file_path), &data)) {
    PLOG(ERROR) << "Can't read crash log: " << dump_file_path.value();
    return false;
  }

  return HandleCrashWithDumpData(data, pid, uid, exe_name,
                                 "" /*non_exe_error_key*/, "" /* dump_dir */,
                                 signal);
}

bool ChromeCollector::HandleCrashThroughMemfd(
    int memfd,
    pid_t pid,
    uid_t uid,
    const std::string& executable_name,
    const std::string& non_exe_error_key,
    const std::string& dump_dir,
    int signal) {
  std::string data;
  if (!util::ReadMemfdToString(memfd, &data)) {
    PLOG(ERROR) << "Can't read crash log from memfd: " << memfd;
    return false;
  }

  return HandleCrashWithDumpData(data, pid, uid, executable_name,
                                 non_exe_error_key, dump_dir, signal);
}

bool ChromeCollector::ParseCrashLog(const std::string& data,
                                    const base::FilePath& dir,
                                    const std::string& basename,
                                    CrashType crash_type,
                                    base::FilePath* payload,
                                    bool* is_lacros_crash) {
  // Initialize value
  *is_lacros_crash = false;
  size_t at = 0;
  while (at < data.size()) {
    // Look for a : followed by a decimal number, followed by another :
    // followed by N bytes of data.
    std::string name, size_string;
    if (!GetDelimitedString(data, ':', at, &name)) {
      LOG(ERROR) << "Can't find : after name @ offset " << at;
      break;
    }
    at += name.size() + 1;  // Skip the name & : delimiter.

    if (!GetDelimitedString(data, ':', at, &size_string)) {
      LOG(ERROR) << "Can't find : after size @ offset " << at;
      break;
    }
    at += size_string.size() + 1;  // Skip the size & : delimiter.

    size_t size;
    if (!base::StringToSizeT(size_string, &size)) {
      LOG(ERROR) << "String not convertible to integer: " << size_string;
      break;
    }

    // Avoid overflow errors that would allow size to be very large but still
    // pass the at + size > data.size() check below.
    if (size >= std::numeric_limits<size_t>::max() - at) {
      LOG(ERROR) << "Bad size " << size << "; too large";
      break;
    }

    // Data would run past the end, did we get a truncated file?
    if (at + size > data.size()) {
      LOG(ERROR) << "Overrun, expected " << size << " bytes of data, got "
                 << (data.size() - at);
      break;
    }

    if (name.find("filename") != std::string::npos) {
      // File.
      // Name will be in a semi-MIME format of
      // <descriptive name>"; filename="<name>"
      // Descriptive name will be upload_file_minidump for minidumps or
      // upload_file_js_stack for JavaScript stack traces.
      std::string desc, filename;
      RE2 re("(.*)\" *; *filename=\"(.*)\"");
      if (!RE2::FullMatch(name.c_str(), re, &desc, &filename)) {
        LOG(ERROR) << "Filename was not in expected format: " << name;
        break;
      }

      if (desc.compare(kDefaultMinidumpName) == 0) {
        // The minidump.
        if (crash_type != kExecutableCrash) {
          LOG(ERROR) << "Only expect minidumps for executable crashes";
          return false;
        }
        if (!payload->empty()) {
          LOG(ERROR) << "Cannot have multiple payload sections; got minidump "
                        "but already wrote "
                     << payload->value();
          return false;
        }
        *payload = GetCrashPath(dir, basename, constants::kMinidumpExtension);
        if (WriteNewFile(*payload,
                         base::StringPiece(data.c_str() + at, size)) != size) {
          // Can't send a crash report without a payload, so just fail.
          LOG(ERROR) << "Failed to write minidump to " << payload->value();
          return false;
        }
      } else if (desc.compare(kDefaultJavaScriptStackName) == 0) {
        // A JavaScript stack trace, from a JavaScript exception
        if (crash_type != kJavaScriptError) {
          LOG(ERROR) << "Only expect JS stacks for JavaScript errors";
          return false;
        }
        if (!payload->empty()) {
          LOG(ERROR) << "Cannot have multiple payload sections; got JS stack "
                        "but already wrote "
                     << payload->value();
          return false;
        }
        *payload =
            GetCrashPath(dir, basename, constants::kJavaScriptStackExtension);
        if (WriteNewFile(*payload,
                         base::StringPiece(data.c_str() + at, size)) != size) {
          // Can't send a crash report without a payload, so just fail.
          LOG(ERROR) << "Failed to write js stack to " << payload->value();
          return false;
        }
      } else {
        // Some other file.
        FilePath path =
            GetCrashPath(dir, basename + "-" + Sanitize(filename), "other");
        if (WriteNewFile(path, base::StringPiece(data.c_str() + at, size)) >=
            0) {
          AddCrashMetaUploadFile(desc, path.BaseName().value());
        }
        // else keep going and upload what we have.
      }
    } else {
      // Other attribute.
      std::string value_str;
      value_str.reserve(size);

      // Since metadata is one line/value the values must be escaped properly.
      for (size_t i = at; i < at + size; i++) {
        switch (data[i]) {
          case '"':
          case '\\':
            value_str.push_back('\\');
            value_str.push_back(data[i]);
            break;

          case '\r':
            value_str += "\\r";
            break;

          case '\n':
            value_str += "\\n";
            break;

          case '\t':
            value_str += "\\t";
            break;

          case '\0':
            value_str += "\\0";
            break;

          default:
            value_str.push_back(data[i]);
            break;
        }
      }
      AddCrashMetaUploadData(name, value_str);
      if (name == constants::kUploadDataKeyProductKey &&
          value_str == constants::kProductNameChromeLacros) {
        *is_lacros_crash = true;
      }
    }

    at += size;
  }

  return at == data.size();
}

void ChromeCollector::AddLogIfNotTooBig(
    const char* log_map_key,
    const base::FilePath& complete_file_name,
    std::map<std::string, base::FilePath>* logs) {
  if (get_bytes_written() <= max_upload_bytes_) {
    (*logs)[log_map_key] = complete_file_name.BaseName();
  } else {
    // Logs were really big, don't upload them.
    LOG(WARNING) << "Skipping upload of " << complete_file_name.value()
                 << " because report size would exceed limit ("
                 << max_upload_bytes_ << "B)";
    // And free up resources to avoid leaving orphaned file around.
    if (!RemoveNewFile(complete_file_name)) {
      LOG(WARNING) << "Could not remove " << complete_file_name.value();
    }
  }
}

std::map<std::string, base::FilePath> ChromeCollector::GetAdditionalLogs(
    const FilePath& dir,
    const std::string& basename,
    const std::string& key_for_logs,
    CrashType crash_type) {
  std::map<std::string, base::FilePath> logs;
  if (get_bytes_written() > max_upload_bytes_) {
    // Minidump is already too big, no point in processing logs or querying
    // debugd.
    LOG(WARNING) << "Skipping upload of supplemental logs because report size "
                 << "already exceeds limit (" << max_upload_bytes_ << "B)";
    return logs;
  }

  // Run the command specified by the config file to gather logs.
  const FilePath chrome_log_path =
      GetCrashPath(dir, basename, kChromeLogFilename).AddExtension("gz");
  if (GetLogContents(log_config_path_, key_for_logs, chrome_log_path)) {
    AddLogIfNotTooBig(kChromeLogFilename, chrome_log_path, &logs);
  }

  // For executable crashes, also attach:
  //   * Info about the GPU state.
  //   * dmesg output. If Chrome is hanging, session_manager's
  //     LivenessCheckerImpl::RequestKernelTraces will dump a bunch of info into
  //     the dmesg output about what, specifically, is stuck. Note: we can't do
  //     this from crash_reporter_logs.conf because we were spawned from Chrome
  //     and thus are not root.
  //
  // For JavaScript errors, the GPU state is likely too low-level to matter and
  // the program isn't hung, so neither of these would be helpful.
  if (crash_type == kExecutableCrash) {
    // For unit testing, debugd_proxy_ isn't initialized, so skip attempting to
    // get the GPU error state & dmesg output from debugd.
    SetUpDBus();
    if (debugd_proxy_) {
      // Chrome has a 12 second timeout for crash_reporter to execute when it
      // invokes it, so use a 5 second timeout here on both our D-Bus calls.
      constexpr int kDebugdCallTimeoutMsec = 5000;

      const FilePath dri_error_state_path =
          GetCrashPath(dir, basename, kGpuStateFilename);
      const FilePath dmesg_out_path =
          GetCrashPath(dir, basename, kDmesgOutputFilename).AddExtension("gz");

      // Since we may be on a tight timeline, call both debugd RPCs in parallel.
      // This saves us a little time; not as much time as you might think
      // because debugd will not run tasks in parallel, but still some. More
      // importantly, it allows us to use a single timeout for both dbus
      // calls -- the dmesg and the DriError will both timeout when 5 seconds
      // pass.
      base::RunLoop run_loop;
      constexpr int kNumAsyncDbusCalls = 2;
      auto one_dbus_complete_closure =
          base::BarrierClosure(kNumAsyncDbusCalls, run_loop.QuitClosure());
      // We can base::Unretained() the various pointers since all the callbacks
      // will happen in the RunLoop::Run before this function exits.
      debugd_proxy_->GetLogAsync(
          "i915_error_state",
          base::BindOnce(&ChromeCollector::HandleDriErrorState,
                         base::Unretained(this), dri_error_state_path,
                         base::Unretained(&logs), one_dbus_complete_closure),
          base::BindOnce(&ChromeCollector::HandleDriErrorStateError,
                         one_dbus_complete_closure),
          kDebugdCallTimeoutMsec);
      // Maximum lines to record from dmesg. sysrq-w regularly produces over
      // 500 lines of output, so we set this pretty high.
      constexpr uint32_t kMaxDmesgLines = 1500;
      const brillo::VariantDictionary dmesg_options = {
          {"tail", kMaxDmesgLines}};
      debugd_proxy_->CallDmesgAsync(
          dmesg_options,
          base::BindOnce(&ChromeCollector::HandleDmesg, base::Unretained(this),
                         dmesg_out_path, base::Unretained(&logs),
                         one_dbus_complete_closure),
          base::BindOnce(&ChromeCollector::HandleDmesgError,
                         one_dbus_complete_closure),
          kDebugdCallTimeoutMsec);

      run_loop.Run();
    }
  }

  return logs;
}

void ChromeCollector::HandleDriErrorState(
    base::FilePath dri_error_state_path,
    std::map<std::string, base::FilePath>* logs,
    base::RepeatingClosure completion_closure,
    const std::string& dri_error_state_str) {
  if (ProcessDriErrorState(dri_error_state_str, dri_error_state_path)) {
    AddLogIfNotTooBig(kGpuStateFilename, dri_error_state_path, logs);
  }
  completion_closure.Run();
}

bool ChromeCollector::ProcessDriErrorState(
    const std::string& dri_error_state_str,
    const base::FilePath& error_state_path) {
  if (dri_error_state_str == "<empty>")
    return false;

  const char kBase64Header[] = "<base64>: ";
  const size_t kBase64HeaderLength = sizeof(kBase64Header) - 1;
  if (dri_error_state_str.compare(0, kBase64HeaderLength, kBase64Header)) {
    LOG(ERROR) << "i915_error_state is missing base64 header";
    return false;
  }

  std::string decoded_error_state;

  if (!brillo::data_encoding::Base64Decode(
          dri_error_state_str.c_str() + kBase64HeaderLength,
          &decoded_error_state)) {
    LOG(ERROR) << "Could not decode i915_error_state";
    return false;
  }

  // We must use WriteNewFile instead of base::WriteFile as we
  // do not want to write with root access to a symlink that an attacker
  // might have created.
  int written = WriteNewFile(error_state_path, decoded_error_state);
  if (written < 0 ||
      static_cast<size_t>(written) != decoded_error_state.length()) {
    PLOG(ERROR) << "Could not write file " << error_state_path.value()
                << " Written: " << written
                << " Len: " << decoded_error_state.length();
    base::DeleteFile(error_state_path);
    return false;
  }

  return true;
}

// static
void ChromeCollector::HandleDriErrorStateError(
    base::RepeatingClosure completion_closure, brillo::Error* error) {
  if (error == nullptr) {
    LOG(ERROR)
        << "Error retrieving DriErrorState from debugd: Call did not return";
  } else {
    LOG(ERROR) << "Error retrieving DriErrorState from debugd: "
               << error->GetMessage();
  }
  completion_closure.Run();
}

void ChromeCollector::HandleDmesg(base::FilePath dmseg_path,
                                  std::map<std::string, base::FilePath>* logs,
                                  base::RepeatingClosure completion_closure,
                                  const std::string& dmesg_out) {
  if (ProcessDmesgOutput(dmesg_out, dmseg_path)) {
    AddLogIfNotTooBig(kDmesgOutputFilename, dmseg_path, logs);
  }
  completion_closure.Run();
}

bool ChromeCollector::ProcessDmesgOutput(std::string dmesg_out,
                                         const base::FilePath& dmseg_path) {
  if (dmesg_out.empty()) {
    return false;
  }
  StripSensitiveData(&dmesg_out);
  if (!WriteNewCompressedFile(dmseg_path, dmesg_out.data(), dmesg_out.size())) {
    PLOG(ERROR) << "Could not write file " << dmseg_path.value();
    base::DeleteFile(dmseg_path);
    return false;
  }

  return true;
}

// static
void ChromeCollector::HandleDmesgError(
    base::RepeatingClosure completion_closure, brillo::Error* error) {
  if (error == nullptr) {
    LOG(ERROR) << "Error retrieving dmesg from debugd: Call did not return";
  } else {
    LOG(ERROR) << "Error retrieving dmesg from debugd: " << error->GetMessage();
  }
  completion_closure.Run();
}

// static
CollectorInfo ChromeCollector::GetHandlerInfo(
    CrashSendingMode mode,
    const std::string& dump_file_path,
    int memfd,
    pid_t pid,
    uid_t uid,
    const std::string& executable_name,
    const std::string& non_exe_error_key,
    const std::string& chrome_dump_dir,
    int signal) {
  CHECK(dump_file_path.empty() || memfd == -1)
      << "--chrome= and --chrome_memfd= cannot be both set";
  if (memfd == -1) {
    CHECK(non_exe_error_key.empty())
        << "--error_key is only for --chrome_memfd crashes";
  }

  auto chrome_collector = std::make_shared<ChromeCollector>(mode);
  return {
      .collector = chrome_collector,
      .handlers = {{
                       .should_handle = !dump_file_path.empty(),
                       .cb = base::BindRepeating(&ChromeCollector::HandleCrash,
                                                 chrome_collector,
                                                 FilePath(dump_file_path), pid,
                                                 uid, executable_name, signal),
                   },
                   {
                       .should_handle = memfd >= 0,
                       .cb = base::BindRepeating(
                           &ChromeCollector::HandleCrashThroughMemfd,
                           chrome_collector, memfd, pid, uid, executable_name,
                           non_exe_error_key, chrome_dump_dir, signal),
                   }},
  };
}

// See chrome's src/components/crash/content/app/breakpad_linux.cc.
// static
const char ChromeCollector::kSuccessMagic[] = "_sys_cr_finished";
