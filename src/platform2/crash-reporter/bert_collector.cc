// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/bert_collector.h"

#include <fcntl.h>
#include <string>
#include <sys/stat.h>

#include <base/files/file_util.h>
#include <base/logging.h>

#include "crash-reporter/constants.h"
#include "crash-reporter/util.h"

using base::FilePath;

namespace {

constexpr char kACPITablePath[] = "/sys/firmware/acpi/tables";
constexpr char kBertTable[] = "BERT";
constexpr char kBertData[] = "data/BERT";
constexpr char kBertErrorName[] = "bert_error";
const char kSignatureKey[] = "sig";

// Validate BERT table signature, length and region length.
bool BertCheckTable(const struct acpi_table_bert& bert_table) {
  if (memcmp(bert_table.signature, ACPI_SIG_BERT, ACPI_NAME_SIZE) != 0)
    return false;
  if (bert_table.length != sizeof(struct acpi_table_bert))
    return false;
  if (bert_table.region_length != 0 &&
      bert_table.region_length < ACPI_BERT_REGION_STRUCT_SIZE)
    return false;

  return true;
}

// Read BERT table and data files.
// BERT stores data in little endian, and we assume the CPU endian is
// also little endian.
bool BertRead(const FilePath& bert_table_path,
              const FilePath& bert_data_path,
              struct acpi_table_bert* bert_table,
              std::string* bert_table_contents,
              std::string* bert_data_contents) {
  // Read BERT table file.
  if (!base::ReadFileToStringWithMaxSize(bert_table_path, bert_table_contents,
                                         sizeof(struct acpi_table_bert))) {
    PLOG(ERROR) << "BERT table file read failed";
    return false;
  }
  memcpy(bert_table, bert_table_contents->data(), sizeof(*bert_table));

  if (!BertCheckTable(*bert_table)) {
    LOG(ERROR) << "Bad data in BERT table";
    return false;
  }

  // Read BERT data file.
  if (!base::ReadFileToStringWithMaxSize(bert_data_path, bert_data_contents,
                                         bert_table->region_length)) {
    PLOG(ERROR) << "BERT data file read failed";
    return false;
  }
  return true;
}

}  // namespace

BERTCollector::BERTCollector()
    : CrashCollector("bert"), acpitable_path_(kACPITablePath) {}

BERTCollector::~BERTCollector() {}

bool BERTCollector::Collect(bool use_saved_lsb) {
  SetUseSavedLsb(use_saved_lsb);

  FilePath root_crash_directory;

  const FilePath bert_table_path = acpitable_path_.Append(kBertTable);
  if (!base::PathExists(bert_table_path)) {
    return false;
  }

  const FilePath bert_data_path = acpitable_path_.Append(kBertData);
  if (!base::PathExists(bert_data_path)) {
    PLOG(ERROR) << bert_data_path.value() << " sysfs data not available";
    return false;
  }

  LOG(INFO) << "BERT error from previous boot (handling)";

  std::string bert_table_contents;
  std::string bert_data_contents;
  struct acpi_table_bert bert_table;
  // Read BERT table and BERT data information.
  if (!BertRead(bert_table_path, bert_data_path, &bert_table,
                &bert_table_contents, &bert_data_contents)) {
    return false;
  }

  // Dump BERT table and BERT data into single bertdump file.
  if (!GetCreatedCrashDirectoryByEuid(constants::kRootUid,
                                      &root_crash_directory, nullptr)) {
    return false;
  }
  std::string dump_basename =
      FormatDumpBasename(kBertErrorName, time(nullptr), 0);
  FilePath bert_crash_path =
      GetCrashPath(root_crash_directory, dump_basename, "bertdump");

  // We must use WriteNewFile instead of base::WriteFile as we
  // do not want to write with root access to a symlink that an attacker
  // might have created.
  if (WriteNewFile(bert_crash_path,
                   base::StringPiece(bert_table_contents.c_str(),
                                     bert_table.length)) != bert_table.length) {
    PLOG(ERROR) << "Failed to write BERT table to " << bert_crash_path.value();
    return false;
  }
  if (!base::AppendToFile(bert_crash_path,
                          base::StringPiece(bert_data_contents.c_str(),
                                            bert_table.region_length))) {
    PLOG(ERROR) << "Failed to write BERT data to " << bert_crash_path.value();
    return false;
  }

  AddCrashMetaData(kSignatureKey, kBertErrorName);

  // Create meta file with bert dump info and finish up.
  FinishCrash(GetCrashPath(root_crash_directory, dump_basename, "meta"),
              kBertErrorName, bert_crash_path.BaseName().value());

  VLOG(3) << "Stored BERT dump to " << bert_crash_path.value();

  return true;
}
