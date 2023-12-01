// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "modemfwd/journal.h"

#include <optional>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file.h>
#include <base/logging.h>
#include <base/stl_util.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/types/optional_util.h>
#include <brillo/proto_file_io.h>
#include <chromeos/switches/modemfwd_switches.h>

#include "modemfwd/firmware_file.h"
#include "modemfwd/logging.h"
#include "modemfwd/modem_helper.h"
#include "modemfwd/proto_bindings/journal_entry.pb.h"

namespace modemfwd {

namespace {

std::string JournalTypeToFirmwareType(int t) {
  switch (t) {
    case JournalEntryType::MAIN:
      return modemfwd::kFwMain;
    case JournalEntryType::CARRIER:
      return modemfwd::kFwCarrier;
    case JournalEntryType::OEM:
      return modemfwd::kFwOem;
    default:
      return std::string();
  }
  NOTREACHED();
}

JournalEntryType FirmwareTypeToJournalType(std::string fw_type) {
  if (fw_type == modemfwd::kFwMain)
    return JournalEntryType::MAIN;
  else if (fw_type == modemfwd::kFwCarrier)
    return JournalEntryType::CARRIER;
  else if (fw_type == modemfwd::kFwOem)
    return JournalEntryType::OEM;
  else
    return JournalEntryType::UNKNOWN;
}

// Returns true if the operation was restarted successfully or false if it
// failed.
bool RestartOperation(const JournalEntry& entry,
                      FirmwareDirectory* firmware_dir,
                      ModemHelperDirectory* helper_dir) {
  ModemHelper* helper = helper_dir->GetHelperForDeviceId(entry.device_id());
  if (!helper) {
    LOG(ERROR) << "Journal contained unfinished operation for device with ID \""
               << entry.device_id()
               << "\" but no helper was found to restart it";
    return false;
  }

  std::string carrier_id(entry.carrier_id());
  FirmwareDirectory::Files res = firmware_dir->FindFirmware(
      entry.device_id(), carrier_id.empty() ? nullptr : &carrier_id);

  std::vector<FirmwareConfig> flashed_fw;
  std::vector<std::string> paths_for_logging;
  // Keep a reference to all temporary uncompressed files.
  std::vector<std::unique_ptr<FirmwareFile>> all_files;
  for (const auto& entry_type : entry.type()) {
    std::string fw_type = JournalTypeToFirmwareType(entry_type);
    FirmwareFileInfo* info = nullptr;
    base::FilePath fw_path;
    std::string fw_version;

    if (fw_type.empty())
      continue;

    switch (entry_type) {
      case JournalEntryType::MAIN:
        info = base::OptionalToPtr<FirmwareFileInfo>(res.main_firmware);
        break;
      case JournalEntryType::CARRIER:
        info = base::OptionalToPtr<FirmwareFileInfo>(res.carrier_firmware);
        break;
      case JournalEntryType::OEM:
        info = base::OptionalToPtr<FirmwareFileInfo>(res.oem_firmware);
        break;
    }

    auto firmware_file = std::make_unique<FirmwareFile>();
    if (info == nullptr ||
        !firmware_file->PrepareFrom(firmware_dir->GetFirmwarePath(), *info)) {
      LOG(ERROR) << "Unfinished \"" << fw_type
                 << "\" firmware flash for device with ID \""
                 << entry.device_id() << "\" but no firmware was found";
      continue;
    }

    flashed_fw.push_back(
        {fw_type, firmware_file->path_on_filesystem(), info->version});
    paths_for_logging.push_back(firmware_file->path_for_logging().value());
    all_files.push_back(std::move(firmware_file));

    // Main firmware may also include associated firmware payloads that we will
    // simply reflash as well.
    if (entry_type == JournalEntryType::MAIN) {
      for (const auto& assoc_entry : res.assoc_firmware) {
        auto assoc_file = std::make_unique<FirmwareFile>();
        if (!assoc_file->PrepareFrom(firmware_dir->GetFirmwarePath(),
                                     assoc_entry.second)) {
          LOG(ERROR) << "Unfinished \"" << fw_type
                     << "\" firmware flash for device with ID \""
                     << entry.device_id() << "\" but no firmware was found";
          continue;
        }

        flashed_fw.push_back({assoc_entry.first,
                              assoc_file->path_on_filesystem(),
                              assoc_entry.second.version});
        paths_for_logging.push_back(assoc_file->path_for_logging().value());
      }
    }
  }
  if (flashed_fw.size() != entry.type_size() || !flashed_fw.size()) {
    LOG(ERROR) << "Malformed journal entry with invalid types.";
    return false;
  }

  ELOG(INFO) << "Journal reflashing firmwares: "
             << base::JoinString(paths_for_logging, ",");
  return helper->FlashFirmwares(flashed_fw);
}

class JournalImpl : public Journal {
 public:
  explicit JournalImpl(base::File journal_file)
      : journal_file_(std::move(journal_file)) {
    // Clearing the journal prevents it from growing without bound but also
    // ensures that if we crash after this point, we won't try to restart
    // any operations an extra time.
    ClearJournalFile();
  }
  JournalImpl(const JournalImpl&) = delete;
  JournalImpl& operator=(const JournalImpl&) = delete;

  void MarkStartOfFlashingFirmware(
      const std::vector<std::string>& firmware_types,
      const std::string& device_id,
      const std::string& carrier_id) override {
    JournalEntry entry;
    entry.set_device_id(device_id);
    entry.set_carrier_id(carrier_id);
    for (const auto& t : firmware_types)
      entry.add_type(FirmwareTypeToJournalType(t));
    WriteJournalEntry(entry);
  }

  void MarkEndOfFlashingFirmware(const std::string& device_id,
                                 const std::string& carrier_id) override {
    JournalEntry entry;
    if (!ReadJournalEntry(&entry)) {
      LOG(ERROR) << __func__ << ": no journal entry to commit";
      return;
    }
    if (entry.device_id() != device_id || entry.carrier_id() != carrier_id) {
      LOG(ERROR) << __func__ << ": found journal entry, but it didn't match";
      return;
    }
    ClearJournalFile();
  }

 private:
  bool ReadJournalEntry(JournalEntry* entry) {
    if (journal_file_.GetLength() == 0) {
      ELOG(INFO) << "Tried to read from empty journal";
      return false;
    }
    journal_file_.Seek(base::File::FROM_BEGIN, 0);
    return brillo::ReadTextProtobuf(journal_file_.GetPlatformFile(), entry);
  }

  bool WriteJournalEntry(const JournalEntry& entry) {
    if (journal_file_.GetLength() > 0) {
      ELOG(INFO) << "Tried to write to journal with uncommitted entry";
      return false;
    }
    journal_file_.Seek(base::File::FROM_BEGIN, 0);
    return brillo::WriteTextProtobuf(journal_file_.GetPlatformFile(), entry);
  }

  void ClearJournalFile() {
    journal_file_.SetLength(0);
    journal_file_.Seek(base::File::FROM_BEGIN, 0);
    journal_file_.Flush();
  }

  base::File journal_file_;
};

}  // namespace

std::unique_ptr<Journal> OpenJournal(const base::FilePath& journal_path,
                                     FirmwareDirectory* firmware_dir,
                                     ModemHelperDirectory* helper_dir) {
  base::File journal_file(journal_path, base::File::FLAG_OPEN_ALWAYS |
                                            base::File::FLAG_READ |
                                            base::File::FLAG_WRITE);
  if (!journal_file.IsValid()) {
    LOG(ERROR) << "Could not open journal file";
    return nullptr;
  }

  // Restart operations if necessary.
  if (journal_file.GetLength() > 0) {
    JournalEntry last_entry;
    if (brillo::ReadTextProtobuf(journal_file.GetPlatformFile(), &last_entry) &&
        !RestartOperation(last_entry, firmware_dir, helper_dir)) {
      LOG(ERROR) << "Failed to restart uncommitted operation";
    }
  }

  return std::make_unique<JournalImpl>(std::move(journal_file));
}

}  // namespace modemfwd
