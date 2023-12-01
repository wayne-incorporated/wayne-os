// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/pending_activation_store.h"

#include <utility>

#include <base/logging.h>
#include <base/notreached.h>

#include "shill/logging.h"
#include "shill/store/key_file_store.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kCellular;
}  // namespace Logging

const char PendingActivationStore::kIccidGroupId[] = "iccid_list";
const char PendingActivationStore::kMeidGroupId[] = "meid_list";
// We're keeping the old file name here for backwards compatibility.
const char PendingActivationStore::kStorageFileName[] =
    "activating_iccid_store.profile";

PendingActivationStore::PendingActivationStore() = default;

PendingActivationStore::~PendingActivationStore() {
  if (storage_)
    storage_->Flush();  // Make certain that everything is persisted.
}

namespace {

std::string StateToString(PendingActivationStore::State state) {
  switch (state) {
    case PendingActivationStore::kStateUnknown:
      return "Unknown";
    case PendingActivationStore::kStatePending:
      return "Pending";
    case PendingActivationStore::kStateActivated:
      return "Activated";
    default:
      return "Invalid";
  }
}

std::string FormattedIdentifier(PendingActivationStore::IdentifierType type,
                                const std::string& identifier) {
  std::string label;
  switch (type) {
    case PendingActivationStore::kIdentifierICCID:
      label = "ICCID";
      break;
    case PendingActivationStore::kIdentifierMEID:
      label = "MEID";
      break;
    default:
      NOTREACHED();
  }
  return "[" + label + "=" + identifier + "]";
}

}  // namespace

// static
std::string PendingActivationStore::IdentifierTypeToGroupId(
    IdentifierType type) {
  switch (type) {
    case kIdentifierICCID:
      return kIccidGroupId;
    case kIdentifierMEID:
      return kMeidGroupId;
    default:
      SLOG(2) << "Incorrect identifier type: " << type;
      return "";
  }
}

bool PendingActivationStore::InitStorage(const base::FilePath& storage_path) {
  // Close the current file.
  if (storage_) {
    storage_->Flush();
    storage_.reset();  // KeyFileStore closes the file in its destructor.
  }
  if (storage_path.empty()) {
    LOG(ERROR) << "Empty storage directory path provided.";
    return false;
  }
  base::FilePath path = storage_path.Append(kStorageFileName);
  std::unique_ptr<StoreInterface> storage = CreateStore(path);
  bool already_exists = !storage->IsEmpty();
  if (!storage->Open()) {
    LOG(ERROR) << "Failed to open file at '" << path.value() << "'";
    if (already_exists)
      storage->MarkAsCorrupted();
    return false;
  }
  if (!already_exists)
    storage->SetHeader("Identifiers pending cellular activation.");
  storage_ = std::move(storage);
  return true;
}

PendingActivationStore::State PendingActivationStore::GetActivationState(
    IdentifierType type, const std::string& identifier) const {
  std::string formatted_identifier = FormattedIdentifier(type, identifier);
  SLOG(2) << __func__ << ": " << formatted_identifier;
  if (!storage_) {
    LOG(ERROR) << "Underlying storage not initialized.";
    return kStateUnknown;
  }
  int state = 0;
  if (!storage_->GetInt(IdentifierTypeToGroupId(type), identifier, &state)) {
    SLOG(2) << "No entry exists for " << formatted_identifier;
    return kStateUnknown;
  }
  if (state <= 0 || state >= kStateMax) {
    SLOG(2) << "State value read for " << formatted_identifier
            << " is invalid.";
    return kStateUnknown;
  }
  return static_cast<State>(state);
}

bool PendingActivationStore::SetActivationState(IdentifierType type,
                                                const std::string& identifier,
                                                State state) {
  SLOG(2) << __func__ << ": State=" << StateToString(state) << ", "
          << FormattedIdentifier(type, identifier);
  if (!storage_) {
    LOG(ERROR) << "Underlying storage not initialized.";
    return false;
  }
  if (state == kStateUnknown) {
    SLOG(2) << "kStateUnknown cannot be used as a value.";
    return false;
  }
  if (state < 0 || state >= kStateMax) {
    SLOG(2) << "Cannot set state to \"" << StateToString(state) << "\"";
    return false;
  }
  if (!storage_->SetInt(IdentifierTypeToGroupId(type), identifier,
                        static_cast<int>(state))) {
    SLOG(2) << "Failed to store the given identifier and state "
            << "values.";
    return false;
  }
  return storage_->Flush();
}

bool PendingActivationStore::RemoveEntry(IdentifierType type,
                                         const std::string& identifier) {
  SLOG(2) << __func__ << ": " << FormattedIdentifier(type, identifier);
  if (!storage_) {
    LOG(ERROR) << "Underlying storage not initialized.";
    return false;
  }
  if (!storage_->DeleteKey(IdentifierTypeToGroupId(type), identifier)) {
    SLOG(2) << "Failed to remove the given identifier.";
    return false;
  }
  return storage_->Flush();
}

}  // namespace shill
