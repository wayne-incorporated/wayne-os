// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_CONSTANTS_H_
#define CRASH_REPORTER_CONSTANTS_H_

#include <sys/stat.h>
#include <unistd.h>

namespace constants {

// UserID for root account.
constexpr uid_t kRootUid = 0;

constexpr char kCrashName[] = "crash";
// The name of the crash-access group, which owns /var/spool/crash.
constexpr char kCrashGroupName[] = "crash-access";

#if !USE_KVM_GUEST
constexpr char kCrashUserGroupName[] = "crash-user-access";
#endif

constexpr char kUploadVarPrefix[] = "upload_var_";
constexpr char kUploadTextPrefix[] = "upload_text_";
constexpr char kUploadFilePrefix[] = "upload_file_";

// An upload var for the metafile, indicating that a crash happened
// in crash loop mode.
constexpr char kCrashLoopModeKey[] = "crash_loop_mode";

// An upload var for the metafile, giving the product name (for example,
// "Chrome_ChromeOS" or "ChromeOS" or "Chrome_Lacros")
constexpr char kUploadDataKeyProductKey[] = "prod";

// The product name for Chrome ash crashes. Must match the string in
// ChromeCrashReporterClient::GetProductNameAndVersion() in the chromium repo.
constexpr char kProductNameChromeAsh[] = "Chrome_ChromeOS";

// The product name for Chrome Lacros crashes. Must match the string in
// ChromeCrashReporterClient::GetProductNameAndVersion() in the chromium repo.
constexpr char kProductNameChromeLacros[] = "Chrome_Lacros";

constexpr char kJavaScriptStackExtension[] = "js_stack";
constexpr char kJavaScriptStackExtensionWithDot[] = ".js_stack";
// This *must match* the crash::FileStorage::kJsStacktraceFileName constant
// in the google3 internal crash processing code.
constexpr char kKindForJavaScriptError[] = "JavascriptError";

constexpr char kMinidumpExtension[] = "dmp";
constexpr char kMinidumpExtensionWithDot[] = ".dmp";
// This *must match* the ending of the crash::FileStorage::kDumpFileName
// in the google3 internal crash processing code.
constexpr char kKindForMinidump[] = "minidump";

constexpr mode_t kSystemCrashFilesMode = 0660;

}  // namespace constants

#endif  // CRASH_REPORTER_CONSTANTS_H_
