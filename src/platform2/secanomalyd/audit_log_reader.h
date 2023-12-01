// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// AuditLogReader is used to read audit records from /var/log/audit/audit.log.
// Parser is used to parse and validate various types of records.

#ifndef SECANOMALYD_AUDIT_LOG_READER_H_
#define SECANOMALYD_AUDIT_LOG_READER_H_

#include "secanomalyd/text_file_reader.h"

#include <cstddef>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <utility>

#include <asm-generic/errno-base.h>
#include <base/files/file_util.h>
#include <base/time/time.h>
#include <re2/re2.h>

namespace secanomalyd {

const base::FilePath kAuditLogPath("/var/log/audit/audit.log");

// Pattern used for catching audit log records of type AVC.
// The first group captures the Unix timestamp (e.g. 1666373231.610) and the
// second group captures the rest of the log message, including all the
// key-value pairs.
// Example of an AVC log record:
// type=AVC msg=audit(1666373231.610:518): ChromeOS LSM: memfd execution
// attempt, cmd="./memfd_test.execv.elf", filename=/proc/self/fd/3
constexpr char kAVCRecordPattern[] = R"(type=AVC [^(]+\(([\d\.]+)\S+ (.+))";

// Pattern used for catching audit log records of type SYSCALL.
// Example of a SYSCALL log record:
// type=SYSCALL msg=audit(1666651511.865:137464): arch=c000003e
// syscall=319 success=yes exit=3 a0=57d1eca43748 a1=2 a2=0 a3=0 items=0
// ppid=3187 pid=19347 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0
// fsgid=0 tty=pts0 ses=12 comm="memfd_test.syml"
// exe="/usr/bin/memfd/memfd_test.symlink" subj=u:r:cros_ssh_session:s0
// key=(null)^]ARCH=x86_64 SYSCALL=memfd_create AUID="root" UID="root"
constexpr char kSyscallRecordPattern[] =
    R"(type=SYSCALL [^(]+\(([\d\.]+)\S+ (.+))";

// Tags are used to uniquely ID various log record types.
constexpr char kAVCRecordTag[] = "AVC";
constexpr char kSyscallRecordTag[] = "SYSCALL";

// Represents a record (one entry) in the audit log file.
// |tag| identifies the type of record and the parser that should be used on it.
// |message| holds the content of the log after the type and the timestamp.
// |timestamp| holds the timestamp of the log, converted to base::Time object.
struct LogRecord {
  std::string tag;
  std::string message;
  base::Time timestamp;
};

// Used as the default value when the executable path cannot be extracted from
// the log message, i.e: the pattern is not as expected.
const char kUnknownExePath[] = "unknown_executable";

// Returns true if the log message indicates a memfd_create syscall that
// succeeded.
bool IsMemfdCreate(const std::string& log_message);

// Returns true if the log message indicates a memfd execution attempt and
// extracts the executable path from the cmd field of the log entry.
bool IsMemfdExecutionAttempt(const std::string& log_message,
                             std::string& exe_path);

// A Parser object is created for each log record type we are interested in.
// Each parser is uniquely identified by a |tag_| that determines the type of
// record it should be used on, and a |pattern_| which matches the pattern for
// the targeted record type.
class Parser {
 public:
  Parser(std::string tag, std::unique_ptr<RE2> pattern)
      : tag_(tag), pattern_(std::move(pattern)) {}
  ~Parser() = default;

  Parser(const Parser&) = delete;
  Parser& operator=(const Parser&) = delete;

  // Determines whether the supplied log line matches the pattern for this
  // parser and parses the log line into the LogRecord data structure.
  bool IsValid(const std::string& line, LogRecord& log_record);

 private:
  const std::string tag_;
  const std::unique_ptr<RE2> pattern_;
};

// AuditLogReader parses newline-delimited log record into structs and uses
// parser objects to determine if the line is valid.
// It uses secanomalyd::TextFileReader for reading lines in the log files and
// handling log rotations.
class AuditLogReader {
 public:
  explicit AuditLogReader(const base::FilePath& path)
      : log_file_path_(path), log_file_(path) {
    parser_map_[kAVCRecordTag] = std::make_unique<Parser>(
        kAVCRecordTag, std::make_unique<RE2>(kAVCRecordPattern));
    parser_map_[kSyscallRecordTag] = std::make_unique<Parser>(
        kSyscallRecordTag, std::make_unique<RE2>(kSyscallRecordPattern));
    // TODO(b/257485632) Seeking to the beginning of the file here makes
    // AuditLogReader susceptible to reporting the same events again if the
    // daemon restarts. However, the target anomaly is expected to rarely occur
    // and the baseline condition is very common so repeat reports shouldn't
    // affect the UMA metric substantially.
    log_file_.SeekToBegin();
  }
  ~AuditLogReader() = default;

  AuditLogReader(const AuditLogReader&) = delete;
  AuditLogReader& operator=(const AuditLogReader&) = delete;

  // Returns true while there are log records in the log file.
  bool GetNextEntry(LogRecord* log_record);

 private:
  // Parses a line from log_file_.
  bool ReadLine(const std::string& line, LogRecord& log_record);

  const base::FilePath log_file_path_;

  // TextFileReader is defined in text_file_reader.h.
  TextFileReader log_file_;

  // Keeps a map of all the parser objects that should be tested against the log
  // records found in the log file.
  std::map<std::string, std::unique_ptr<Parser>> parser_map_;

  FRIEND_TEST(AuditLogReaderTest, AuditLogReaderTest);
};

}  // namespace secanomalyd

#endif  // SECANOMALYD_AUDIT_LOG_READER_H_
