// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dlp/dlp_adaptor.h"

#include <cstdint>
#include <set>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/containers/contains.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/process/process_handle.h>
#include <base/strings/string_number_conversions.h>
#include <base/task/single_thread_task_runner.h>
#include <base/time/time.h>
#include <brillo/dbus/dbus_object.h>
#include <brillo/errors/error.h>
#include <dbus/dlp/dbus-constants.h>
#include <featured/feature_library.h>
#include <google/protobuf/message_lite.h>
#include <session_manager/dbus-proxies.h>
#include <sqlite3.h>

#include "dlp/proto_bindings/dlp_service.pb.h"

namespace dlp {

namespace {

// Serializes |proto| to a vector of bytes. CHECKs for success (should
// never fail if there are no required proto fields).
std::vector<uint8_t> SerializeProto(
    const google::protobuf::MessageLite& proto) {
  std::vector<uint8_t> proto_blob(proto.ByteSizeLong());
  CHECK(proto.SerializeToArray(proto_blob.data(), proto_blob.size()));
  return proto_blob;
}

// Parses a proto from an array of bytes |proto_blob|. Returns
// error message or empty string if no error.
std::string ParseProto(const base::Location& from_here,
                       google::protobuf::MessageLite* proto,
                       const std::vector<uint8_t>& proto_blob) {
  if (!proto->ParseFromArray(proto_blob.data(), proto_blob.size())) {
    const std::string error_message = "Failed to parse proto message.";
    LOG(ERROR) << from_here.ToString() << " " << error_message;
    return error_message;
  }
  return "";
}

FileEntry ConvertToFileEntry(ino_t inode, AddFileRequest request) {
  FileEntry result;
  result.inode = inode;
  if (request.has_source_url())
    result.source_url = request.source_url();
  if (request.has_referrer_url())
    result.referrer_url = request.referrer_url();
  return result;
}

std::set<std::pair<base::FilePath, ino64_t>> EnumerateFiles(
    const base::FilePath& root_path) {
  std::set<std::pair<base::FilePath, ino64_t>> files;
  base::FileEnumerator enumerator(root_path, /*recursive=*/true,
                                  base::FileEnumerator::FILES);
  for (base::FilePath entry = enumerator.Next(); !entry.empty();
       entry = enumerator.Next()) {
    files.insert(std::make_pair(entry, enumerator.GetInfo().stat().st_ino));
  }

  return files;
}

// Checks whether the list of the rules is exactly the same.
bool SameRules(const std::vector<DlpFilesRule> rules1,
               const std::vector<DlpFilesRule> rules2) {
  if (rules1.size() != rules2.size()) {
    return false;
  }
  for (int i = 0; i < rules1.size(); ++i) {
    if (SerializeProto(rules1[i]) != SerializeProto(rules2[i])) {
      return false;
    }
  }
  return true;
}

// Whether the cached level should be re-checked.
bool RequiresCheck(RestrictionLevel level) {
  return level == LEVEL_UNSPECIFIED || level == LEVEL_WARN_CANCEL;
}

// If the action is permanently blocked by the current policy.
bool IsAlwaysBlocked(RestrictionLevel level) {
  return level == LEVEL_BLOCK;
}

}  // namespace

const struct VariationsFeature kCrOSLateBootDlpDatabaseCleanupFeature = {
    .name = "CrOSLateBootDlpDatabaseCleanupFeature",
    .default_state = FEATURE_DISABLED_BY_DEFAULT,
};

DlpAdaptor::DlpAdaptor(
    std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object,
    feature::PlatformFeaturesInterface* feature_lib,
    int fanotify_perm_fd,
    int fanotify_notif_fd,
    const base::FilePath& home_path)
    : org::chromium::DlpAdaptor(this),
      dbus_object_(std::move(dbus_object)),
      feature_lib_(feature_lib),
      home_path_(home_path) {
  dlp_metrics_ = std::make_unique<DlpMetrics>();
  fanotify_watcher_ = std::make_unique<FanotifyWatcher>(this, fanotify_perm_fd,
                                                        fanotify_notif_fd);
  dlp_files_policy_service_ =
      std::make_unique<org::chromium::DlpFilesPolicyServiceProxy>(
          dbus_object_->GetBus().get(), kDlpFilesPolicyServiceName);
}

DlpAdaptor::~DlpAdaptor() {
  if (!pending_files_to_add_.empty()) {
    DCHECK(!db_);
    dlp_metrics_->SendAdaptorError(
        AdaptorError::kAddFileNotCompleteBeforeDestruction);
  }
}

void DlpAdaptor::RegisterAsync(
    brillo::dbus_utils::AsyncEventSequencer::CompletionAction
        completion_callback) {
  RegisterWithDBusObject(dbus_object_.get());
  dbus_object_->RegisterAsync(std::move(completion_callback));
}

std::vector<uint8_t> DlpAdaptor::SetDlpFilesPolicy(
    const std::vector<uint8_t>& request_blob) {
  LOG(INFO) << "Received DLP files policy.";

  SetDlpFilesPolicyRequest request;
  std::string error_message = ParseProto(FROM_HERE, &request, request_blob);

  SetDlpFilesPolicyResponse response;
  if (!error_message.empty()) {
    response.set_error_message(error_message);
    dlp_metrics_->SendAdaptorError(AdaptorError::kInvalidProtoError);
    return SerializeProto(response);
  }

  auto new_rules =
      std::vector<DlpFilesRule>(request.rules().begin(), request.rules().end());

  // No update is needed.
  if (SameRules(policy_rules_, new_rules)) {
    return SerializeProto(response);
  }
  requests_cache_.ResetCache();
  policy_rules_.swap(new_rules);

  if (!policy_rules_.empty()) {
    EnsureFanotifyWatcherStarted();
  } else {
    fanotify_watcher_->SetActive(false);
  }

  return SerializeProto(response);
}

void DlpAdaptor::AddFile(
    std::unique_ptr<
        brillo::dbus_utils::DBusMethodResponse<std::vector<uint8_t>>> response,
    const std::vector<uint8_t>& request_blob) {
  AddFileRequest request;

  const std::string parse_error = ParseProto(FROM_HERE, &request, request_blob);
  if (!parse_error.empty()) {
    ReplyOnAddFile(std::move(response),
                   "Failed to parse AddFile request: " + parse_error);
    dlp_metrics_->SendAdaptorError(AdaptorError::kInvalidProtoError);
    return;
  }

  LOG(INFO) << "Adding file to the database: " << request.file_path();

  const ino_t inode = GetInodeValue(request.file_path());
  if (!inode) {
    ReplyOnAddFile(std::move(response), "Failed to get inode");
    dlp_metrics_->SendAdaptorError(AdaptorError::kInodeRetrievalError);
    return;
  }

  FileEntry file_entry = ConvertToFileEntry(inode, request);

  if (!db_) {
    LOG(WARNING) << "Database is not ready, pending addition of the file";
    pending_files_to_add_.push_back(file_entry);
    ReplyOnAddFile(std::move(response), std::string());
    dlp_metrics_->SendAdaptorError(AdaptorError::kDatabaseNotReadyError);
    return;
  }

  db_->InsertFileEntry(
      file_entry,
      base::BindOnce(&DlpAdaptor::OnFileInserted, base::Unretained(this),
                     std::move(response), request.file_path(), inode));
}

void DlpAdaptor::AddFiles(
    std::unique_ptr<
        brillo::dbus_utils::DBusMethodResponse<std::vector<uint8_t>>> response,
    const std::vector<uint8_t>& request_blob) {
  AddFilesRequest request;

  const std::string parse_error = ParseProto(FROM_HERE, &request, request_blob);
  if (!parse_error.empty()) {
    ReplyOnAddFiles(std::move(response),
                    "Failed to parse AddFile request: " + parse_error);
    dlp_metrics_->SendAdaptorError(AdaptorError::kInvalidProtoError);
    return;
  }

  if (request.add_file_requests().empty()) {
    ReplyOnAddFiles(std::move(response), std::string());
    return;
  }

  LOG(INFO) << "Adding " << request.add_file_requests().size()
            << " files to the database.";

  std::vector<FileEntry> files_to_add;
  std::vector<base::FilePath> files_paths;
  std::vector<ino_t> files_inodes;
  for (const AddFileRequest& add_file_request : request.add_file_requests()) {
    LOG(INFO) << "Adding file to the database: "
              << add_file_request.file_path();

    const ino_t inode = GetInodeValue(add_file_request.file_path());
    if (!inode) {
      ReplyOnAddFiles(std::move(response), "Failed to get inode");
      dlp_metrics_->SendAdaptorError(AdaptorError::kInodeRetrievalError);
      return;
    }

    FileEntry file_entry = ConvertToFileEntry(inode, add_file_request);
    files_to_add.push_back(file_entry);
    files_paths.emplace_back(add_file_request.file_path());
    files_inodes.emplace_back(inode);
  }

  if (!db_) {
    LOG(WARNING) << "Database is not ready, pending addition of the file";
    pending_files_to_add_.insert(pending_files_to_add_.end(),
                                 files_to_add.begin(), files_to_add.end());
    ReplyOnAddFiles(std::move(response), std::string());
    dlp_metrics_->SendAdaptorError(AdaptorError::kDatabaseNotReadyError);
    return;
  }

  db_->InsertFileEntries(
      files_to_add,
      base::BindOnce(&DlpAdaptor::OnFilesInserted, base::Unretained(this),
                     std::move(response), std::move(files_paths),
                     std::move(files_inodes)));
}

void DlpAdaptor::RequestFileAccess(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<std::vector<uint8_t>,
                                                           base::ScopedFD>>
        response,
    const std::vector<uint8_t>& request_blob) {
  base::ScopedFD local_fd, remote_fd;
  if (!base::CreatePipe(&local_fd, &remote_fd, /*non_blocking=*/true)) {
    PLOG(ERROR) << "Failed to create lifeline pipe";
    dlp_metrics_->SendAdaptorError(AdaptorError::kCreatePipeError);
    std::move(response)->ReplyWithError(
        FROM_HERE, brillo::errors::dbus::kDomain, dlp::kErrorFailedToCreatePipe,
        "Failed to create lifeline pipe");
    return;
  }
  RequestFileAccessRequest request;

  const std::string parse_error = ParseProto(FROM_HERE, &request, request_blob);
  if (!parse_error.empty()) {
    LOG(ERROR) << "Failed to parse RequestFileAccess request: " << parse_error;
    dlp_metrics_->SendAdaptorError(AdaptorError::kInvalidProtoError);
    ReplyOnRequestFileAccess(std::move(response), std::move(remote_fd),
                             /*allowed=*/false, parse_error);
    return;
  }

  if (!db_) {
    ReplyOnRequestFileAccess(std::move(response), std::move(remote_fd),
                             /*allowed=*/true,
                             /*error_message=*/std::string());
    return;
  }

  std::vector<ino64_t> inodes;
  for (const auto& file_path : request.files_paths()) {
    const ino_t inode_n = GetInodeValue(file_path);
    if (inode_n > 0) {
      inodes.push_back(inode_n);
    }
  }

  // If no valid inodes provided, return immediately.
  if (inodes.empty()) {
    ReplyOnRequestFileAccess(std::move(response), std::move(remote_fd),
                             /*allowed=*/true,
                             /*error_message=*/std::string());
    return;
  }

  db_->GetFileEntriesByInodes(
      inodes, base::BindOnce(&DlpAdaptor::ProcessRequestFileAccessWithData,
                             base::Unretained(this), std::move(response),
                             std::move(request), std::move(local_fd),
                             std::move(remote_fd)));
}

void DlpAdaptor::ProcessRequestFileAccessWithData(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<std::vector<uint8_t>,
                                                           base::ScopedFD>>
        response,
    RequestFileAccessRequest request,
    base::ScopedFD local_fd,
    base::ScopedFD remote_fd,
    std::map<ino64_t, FileEntry> file_entries) {
  IsFilesTransferRestrictedRequest matching_request;
  std::vector<ino64_t> request_inodes;
  std::vector<ino64_t> granted_inodes;

  for (const auto& file_path : request.files_paths()) {
    const ino_t inode_n = GetInodeValue(file_path);
    auto it = file_entries.find(inode_n);
    if (it == std::end(file_entries)) {
      // Skip file if it's not DLP-protected as access to it is always allowed.
      continue;
    }
    RestrictionLevel cached_level = requests_cache_.Get(
        inode_n, file_path,
        request.has_destination_url() ? request.destination_url() : "",
        request.has_destination_component() ? request.destination_component()
                                            : DlpComponent::UNKNOWN_COMPONENT);
    // Reply immediately is a file is always blocked.
    if (IsAlwaysBlocked(cached_level)) {
      ReplyOnRequestFileAccess(std::move(response), std::move(remote_fd),
                               /*allowed=*/false,
                               /*error_message=*/std::string());
      return;
    }
    // Was previously allowed, no need to check again.
    if (!RequiresCheck(cached_level)) {
      granted_inodes.emplace_back(inode_n);
      continue;
    }

    request_inodes.push_back(inode_n);

    FileMetadata* file_metadata = matching_request.add_transferred_files();
    file_metadata->set_inode(inode_n);
    file_metadata->set_source_url(it->second.source_url);
    file_metadata->set_path(file_path);
  }
  // If access to all requested files was allowed, return immediately.
  if (request_inodes.empty()) {
    if (!granted_inodes.empty()) {
      int lifeline_fd = AddLifelineFd(local_fd.get());
      approved_requests_.insert_or_assign(
          lifeline_fd,
          std::make_pair(std::move(granted_inodes), request.process_id()));
    }

    ReplyOnRequestFileAccess(std::move(response), std::move(remote_fd),
                             /*allowed=*/true,
                             /*error_message=*/std::string());
    return;
  }

  std::pair<RequestFileAccessCallback, RequestFileAccessCallback> callbacks =
      base::SplitOnceCallback(base::BindOnce(
          &DlpAdaptor::ReplyOnRequestFileAccess, base::Unretained(this),
          std::move(response), std::move(remote_fd)));

  if (request.has_destination_url())
    matching_request.set_destination_url(request.destination_url());
  if (request.has_destination_component())
    matching_request.set_destination_component(request.destination_component());

  matching_request.set_file_action(FileAction::TRANSFER);

  auto cache_callback =
      base::BindOnce(&DlpRequestsCache::CacheResult,
                     base::Unretained(&requests_cache_), matching_request);

  dlp_files_policy_service_->IsFilesTransferRestrictedAsync(
      SerializeProto(matching_request),
      base::BindOnce(&DlpAdaptor::OnRequestFileAccess, base::Unretained(this),
                     std::move(request_inodes), std::move(granted_inodes),
                     request.process_id(), std::move(local_fd),
                     std::move(callbacks.first), std::move(cache_callback)),
      base::BindOnce(&DlpAdaptor::OnRequestFileAccessError,
                     base::Unretained(this), std::move(callbacks.second)),
      /*timeout_ms=*/base::Minutes(5).InMilliseconds());
}

void DlpAdaptor::GetFilesSources(
    std::unique_ptr<
        brillo::dbus_utils::DBusMethodResponse<std::vector<uint8_t>>> response,
    const std::vector<uint8_t>& request_blob) {
  GetFilesSourcesRequest request;
  GetFilesSourcesResponse response_proto;
  const std::string parse_error = ParseProto(FROM_HERE, &request, request_blob);
  if (!parse_error.empty()) {
    LOG(ERROR) << "Failed to parse GetFilesSources request: " << parse_error;
    dlp_metrics_->SendAdaptorError(AdaptorError::kInvalidProtoError);
    response_proto.set_error_message(parse_error);
    response->Return(SerializeProto(response_proto));
    return;
  }

  if (!db_) {
    dlp_metrics_->SendAdaptorError(AdaptorError::kDatabaseNotReadyError);
    response_proto.set_error_message("Database not ready");
    response->Return(SerializeProto(response_proto));
    return;
  }

  const std::vector<ino64_t> inodes = {request.files_inodes().begin(),
                                       request.files_inodes().end()};

  db_->GetFileEntriesByInodes(
      inodes,
      base::BindOnce(&DlpAdaptor::ProcessGetFilesSourcesWithData,
                     base::Unretained(this), std::move(response), inodes));
}

void DlpAdaptor::CheckFilesTransfer(
    std::unique_ptr<
        brillo::dbus_utils::DBusMethodResponse<std::vector<uint8_t>>> response,
    const std::vector<uint8_t>& request_blob) {
  CheckFilesTransferRequest request;
  CheckFilesTransferResponse response_proto;
  const std::string parse_error = ParseProto(FROM_HERE, &request, request_blob);
  if (!parse_error.empty()) {
    LOG(ERROR) << "Failed to parse CheckFilesTransfer request: " << parse_error;
    dlp_metrics_->SendAdaptorError(AdaptorError::kInvalidProtoError);
    response_proto.set_error_message(parse_error);
    response->Return(SerializeProto(response_proto));
    return;
  }

  if (!db_) {
    dlp_metrics_->SendAdaptorError(AdaptorError::kDatabaseNotReadyError);
    response_proto.set_error_message("Database is not ready");
    response->Return(SerializeProto(response_proto));
    return;
  }

  std::vector<ino64_t> inodes;
  for (const auto& file_path : request.files_paths()) {
    const ino_t file_inode = GetInodeValue(file_path);
    if (file_inode > 0) {
      inodes.push_back(file_inode);
    }
  }

  db_->GetFileEntriesByInodes(
      inodes, base::BindOnce(&DlpAdaptor::ProcessCheckFilesTransferWithData,
                             base::Unretained(this), std::move(response),
                             std::move(request)));
}

void DlpAdaptor::SetFanotifyWatcherStartedForTesting(bool is_started) {
  is_fanotify_watcher_started_for_testing_ = is_started;
}

void DlpAdaptor::CloseDatabaseForTesting() {
  db_.reset();
}

void DlpAdaptor::InitDatabase(const base::FilePath& database_path,
                              base::OnceClosure init_callback) {
  LOG(INFO) << "Opening database in: " << database_path.value();
  const base::FilePath database_file = database_path.Append("database");
  if (!base::PathExists(database_file)) {
    LOG(INFO) << "Creating database file";
    base::WriteFile(database_path, "\0", 1);
  }
  std::unique_ptr<DlpDatabase> db =
      std::make_unique<DlpDatabase>(database_file, this);
  DlpDatabase* db_ptr = db.get();

  db_ptr->Init(base::BindOnce(&DlpAdaptor::OnDatabaseInitialized,
                              base::Unretained(this), std::move(init_callback),
                              std::move(db), database_path));
}

void DlpAdaptor::OnDatabaseInitialized(base::OnceClosure init_callback,
                                       std::unique_ptr<DlpDatabase> db,
                                       const base::FilePath& database_path,
                                       int db_status) {
  if (db_status != SQLITE_OK) {
    LOG(ERROR) << "Cannot connect to database " << database_path;
    dlp_metrics_->SendAdaptorError(AdaptorError::kDatabaseConnectionError);
    std::move(init_callback).Run();
    return;
  }

  if (!pending_files_to_add_.empty()) {
    LOG(INFO) << "Inserting pending entries";
    DlpDatabase* db_ptr = db.get();
    std::vector<FileEntry> files_being_added;
    files_being_added.swap(pending_files_to_add_);
    db_ptr->InsertFileEntries(
        files_being_added,
        base::BindOnce(&DlpAdaptor::OnPendingFilesInserted,
                       base::Unretained(this), std::move(init_callback),
                       std::move(db), database_path, db_status));
    return;
  }

  // Check whether cleanup of deleted files should happen when database is
  // initialized.
  // This could be disabled because for now the daemon can't traverse some
  // of the home directory folders due to inconsistent access permissions.
  if (feature_lib_ &&
      feature_lib_->IsEnabledBlocking(kCrOSLateBootDlpDatabaseCleanupFeature)) {
    base::SingleThreadTaskRunner::GetCurrentDefault()
        ->PostTaskAndReplyWithResult(
            FROM_HERE, base::BindOnce(&EnumerateFiles, home_path_),
            base::BindOnce(&DlpAdaptor::CleanupAndSetDatabase,
                           base::Unretained(this), std::move(db),
                           std::move(init_callback)));
  } else {
    OnDatabaseCleaned(std::move(db), std::move(init_callback),
                      /*success=*/true);
  }
}

void DlpAdaptor::OnPendingFilesInserted(base::OnceClosure init_callback,
                                        std::unique_ptr<DlpDatabase> db,
                                        const base::FilePath& database_path,
                                        int db_status,
                                        bool success) {
  if (!success) {
    LOG(ERROR) << "Error while adding pending files.";
    dlp_metrics_->SendAdaptorError(AdaptorError::kAddFileError);
  }
  OnDatabaseInitialized(std::move(init_callback), std::move(db), database_path,
                        db_status);
}

void DlpAdaptor::AddPerFileWatch(
    const std::set<std::pair<base::FilePath, ino64_t>>& files) {
  if (!fanotify_watcher_->IsActive())
    return;

  std::vector<ino64_t> inodes;
  for (const auto& entry : files) {
    inodes.push_back(entry.second);
  }

  db_->GetFileEntriesByInodes(
      inodes, base::BindOnce(&DlpAdaptor::ProcessAddPerFileWatchWithData,
                             base::Unretained(this), files));
}

void DlpAdaptor::ProcessAddPerFileWatchWithData(
    const std::set<std::pair<base::FilePath, ino64_t>>& files,
    std::map<ino64_t, FileEntry> file_entries) {
  for (const auto& entry : files) {
    if (file_entries.find(entry.second) != std::end(file_entries)) {
      fanotify_watcher_->AddFileDeleteWatch(entry.first);
    }
  }
}

void DlpAdaptor::EnsureFanotifyWatcherStarted() {
  if (fanotify_watcher_->IsActive())
    return;

  if (is_fanotify_watcher_started_for_testing_)
    return;

  LOG(INFO) << "Activating fanotify watcher";

  fanotify_watcher_->SetActive(true);

  // If the database is not initialized yet, we delay adding per file watch
  // till it'll be created.
  if (db_) {
    base::SingleThreadTaskRunner::GetCurrentDefault()
        ->PostTaskAndReplyWithResult(
            FROM_HERE, base::BindOnce(&EnumerateFiles, home_path_),
            base::BindOnce(&DlpAdaptor::AddPerFileWatch,
                           base::Unretained(this)));
  } else {
    pending_per_file_watches_ = true;
  }
}

void DlpAdaptor::ProcessFileOpenRequest(
    ino_t inode, int pid, base::OnceCallback<void(bool)> callback) {
  if (pid == base::GetCurrentProcId()) {
    // Allowing itself all file accesses (to database files).
    std::move(callback).Run(/*allowed=*/true);
    return;
  }

  if (!db_) {
    LOG(WARNING) << "DLP database is not ready yet. Allowing the file request";
    dlp_metrics_->SendAdaptorError(AdaptorError::kDatabaseNotReadyError);
    std::move(callback).Run(/*allowed=*/true);
    return;
  }

  db_->GetFileEntriesByInodes(
      {inode},
      base::BindOnce(&DlpAdaptor::ProcessFileOpenRequestWithData,
                     base::Unretained(this), pid, std::move(callback)));
}

void DlpAdaptor::ProcessFileOpenRequestWithData(
    int pid,
    base::OnceCallback<void(bool)> callback,
    std::map<ino64_t, FileEntry> file_entries) {
  if (file_entries.size() != 1) {
    std::move(callback).Run(/*allowed=*/true);
    return;
  }
  const FileEntry& file_entry = file_entries.cbegin()->second;

  int lifeline_fd = -1;
  for (const auto& [key, value] : approved_requests_) {
    if (base::Contains(value.first, file_entry.inode) && value.second == pid) {
      lifeline_fd = key;
      break;
    }
  }
  if (lifeline_fd != -1) {
    std::move(callback).Run(/*allowed=*/true);
    return;
  }

  // If the file can be restricted by any DLP rule, do not allow access there.
  IsDlpPolicyMatchedRequest request;
  request.mutable_file_metadata()->set_inode(file_entry.inode);
  request.mutable_file_metadata()->set_source_url(file_entry.source_url);
  // TODO(crbug.com/1357967)
  // request.mutable_file_metadata()->set_path();

  std::pair<base::OnceCallback<void(bool)>, base::OnceCallback<void(bool)>>
      callbacks = base::SplitOnceCallback(std::move(callback));
  dlp_files_policy_service_->IsDlpPolicyMatchedAsync(
      SerializeProto(request),
      base::BindOnce(&DlpAdaptor::OnDlpPolicyMatched, base::Unretained(this),
                     std::move(callbacks.first)),
      base::BindOnce(&DlpAdaptor::OnDlpPolicyMatchedError,
                     base::Unretained(this), std::move(callbacks.second)));
}

void DlpAdaptor::OnFileDeleted(ino_t inode) {
  if (!db_) {
    LOG(WARNING) << "DLP database is not ready yet.";
    dlp_metrics_->SendAdaptorError(AdaptorError::kDatabaseNotReadyError);
    return;
  }

  db_->DeleteFileEntryByInode(inode,
                              /*callback=*/base::DoNothing());
}

void DlpAdaptor::OnFanotifyError(FanotifyError error) {
  dlp_metrics_->SendFanotifyError(error);
}

void DlpAdaptor::OnDatabaseError(DatabaseError error) {
  dlp_metrics_->SendDatabaseError(error);
}

void DlpAdaptor::OnDlpPolicyMatched(base::OnceCallback<void(bool)> callback,
                                    const std::vector<uint8_t>& response_blob) {
  IsDlpPolicyMatchedResponse response;
  std::string parse_error = ParseProto(FROM_HERE, &response, response_blob);
  if (!parse_error.empty()) {
    LOG(ERROR) << "Failed to parse IsDlpPolicyMatched response: "
               << parse_error;
    dlp_metrics_->SendAdaptorError(AdaptorError::kInvalidProtoError);
    std::move(callback).Run(/*allowed=*/false);
    return;
  }
  std::move(callback).Run(!response.restricted());
}

void DlpAdaptor::OnDlpPolicyMatchedError(
    base::OnceCallback<void(bool)> callback, brillo::Error* error) {
  LOG(ERROR) << "Failed to check whether file could be restricted";
  dlp_metrics_->SendAdaptorError(AdaptorError::kRestrictionDetectionError);
  std::move(callback).Run(/*allowed=*/false);
}

void DlpAdaptor::OnRequestFileAccess(
    std::vector<uint64_t> request_inodes,
    std::vector<uint64_t> granted_inodes,
    int pid,
    base::ScopedFD local_fd,
    RequestFileAccessCallback callback,
    base::OnceCallback<void(IsFilesTransferRestrictedResponse)> cache_callback,
    const std::vector<uint8_t>& response_blob) {
  IsFilesTransferRestrictedResponse response;
  std::string parse_error = ParseProto(FROM_HERE, &response, response_blob);
  if (!parse_error.empty()) {
    LOG(ERROR) << "Failed to parse IsFilesTransferRestrictedResponse response: "
               << parse_error;
    dlp_metrics_->SendAdaptorError(AdaptorError::kInvalidProtoError);
    std::move(callback).Run(
        /*allowed=*/false, parse_error);
    return;
  }

  // Cache the response.
  std::move(cache_callback).Run(response);

  bool allowed = true;
  for (const auto& file : response.files_restrictions()) {
    if (file.restriction_level() == ::dlp::RestrictionLevel::LEVEL_BLOCK ||
        file.restriction_level() ==
            ::dlp::RestrictionLevel::LEVEL_WARN_CANCEL) {
      allowed = false;
      break;
    }
  }

  if (allowed) {
    request_inodes.insert(request_inodes.end(), granted_inodes.begin(),
                          granted_inodes.end());
    int lifeline_fd = AddLifelineFd(local_fd.get());
    approved_requests_.insert_or_assign(
        lifeline_fd, std::make_pair(std::move(request_inodes), pid));
  }

  std::move(callback).Run(allowed, /*error_message=*/std::string());
}

void DlpAdaptor::OnRequestFileAccessError(RequestFileAccessCallback callback,
                                          brillo::Error* error) {
  LOG(ERROR) << "Failed to check whether file could be restricted";
  dlp_metrics_->SendAdaptorError(AdaptorError::kRestrictionDetectionError);
  std::move(callback).Run(/*allowed=*/false, error->GetMessage());
}

void DlpAdaptor::ReplyOnRequestFileAccess(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<std::vector<uint8_t>,
                                                           base::ScopedFD>>
        response,
    base::ScopedFD remote_fd,
    bool allowed,
    const std::string& error_message) {
  RequestFileAccessResponse response_proto;
  response_proto.set_allowed(allowed);
  if (!error_message.empty())
    response_proto.set_error_message(error_message);
  response->Return(SerializeProto(response_proto), std::move(remote_fd));
}

void DlpAdaptor::OnFileInserted(
    std::unique_ptr<
        brillo::dbus_utils::DBusMethodResponse<std::vector<uint8_t>>> response,
    const std::string& file_path,
    ino_t inode,
    bool success) {
  if (success) {
    AddPerFileWatch({std::make_pair(base::FilePath(file_path), inode)});
    ReplyOnAddFile(std::move(response), std::string());
  } else {
    ReplyOnAddFile(std::move(response), "Failed to add entry to database");
  }
}

void DlpAdaptor::OnFilesInserted(
    std::unique_ptr<
        brillo::dbus_utils::DBusMethodResponse<std::vector<uint8_t>>> response,
    std::vector<base::FilePath> files_paths,
    std::vector<ino_t> files_inodes,
    bool success) {
  CHECK(files_paths.size() == files_inodes.size());
  if (success) {
    for (size_t i = 0; i < files_paths.size(); ++i) {
      AddPerFileWatch({std::make_pair(files_paths[i], files_inodes[i])});
    }
    ReplyOnAddFile(std::move(response), std::string());
  } else {
    ReplyOnAddFile(std::move(response), "Failed to add entries to database");
  }
}

void DlpAdaptor::ReplyOnAddFile(
    std::unique_ptr<
        brillo::dbus_utils::DBusMethodResponse<std::vector<uint8_t>>> response,
    std::string error_message) {
  AddFileResponse response_proto;
  if (!error_message.empty()) {
    LOG(ERROR) << "Error while adding file: " << error_message;
    dlp_metrics_->SendAdaptorError(AdaptorError::kAddFileError);
    response_proto.set_error_message(error_message);
  }
  response->Return(SerializeProto(response_proto));
}

void DlpAdaptor::ReplyOnAddFiles(
    std::unique_ptr<
        brillo::dbus_utils::DBusMethodResponse<std::vector<uint8_t>>> response,
    std::string error_message) {
  AddFilesResponse response_proto;
  if (!error_message.empty()) {
    LOG(ERROR) << "Error while adding file: " << error_message;
    dlp_metrics_->SendAdaptorError(AdaptorError::kAddFileError);
    response_proto.set_error_message(error_message);
  }
  response->Return(SerializeProto(response_proto));
}

void DlpAdaptor::ProcessCheckFilesTransferWithData(
    std::unique_ptr<
        brillo::dbus_utils::DBusMethodResponse<std::vector<uint8_t>>> response,
    CheckFilesTransferRequest request,
    std::map<ino64_t, FileEntry> file_entries) {
  CheckFilesTransferResponse response_proto;

  IsFilesTransferRestrictedRequest matching_request;
  base::flat_set<std::string> files_to_check;
  std::vector<std::string> already_restricted;
  for (const auto& file_path : request.files_paths()) {
    const ino_t file_inode = GetInodeValue(file_path);
    auto it = file_entries.find(file_inode);
    if (it == std::end(file_entries)) {
      // Skip file if it's not DLP-protected as access to it is always allowed.
      continue;
    }

    RestrictionLevel cached_level = requests_cache_.Get(
        file_inode, file_path,
        request.has_destination_url() ? request.destination_url() : "",
        request.has_destination_component() ? request.destination_component()
                                            : DlpComponent::UNKNOWN_COMPONENT);
    // The file is always blocked.
    if (IsAlwaysBlocked(cached_level)) {
      already_restricted.push_back(file_path);
    }
    // Was previously allowed/blocked, no need to check again.
    if (!RequiresCheck(cached_level)) {
      continue;
    }

    files_to_check.insert(file_path);

    FileMetadata* file_metadata = matching_request.add_transferred_files();
    file_metadata->set_inode(file_inode);
    file_metadata->set_source_url(it->second.source_url);
    file_metadata->set_path(file_path);
  }

  if (files_to_check.empty()) {
    ReplyOnCheckFilesTransfer(std::move(response),
                              std::move(already_restricted),
                              /*error_message=*/std::string());
    return;
  }

  if (request.has_destination_url())
    matching_request.set_destination_url(request.destination_url());
  if (request.has_destination_component())
    matching_request.set_destination_component(request.destination_component());
  if (request.has_file_action())
    matching_request.set_file_action(request.file_action());
  if (request.has_io_task_id())
    matching_request.set_io_task_id(request.io_task_id());

  auto callbacks = base::SplitOnceCallback(
      base::BindOnce(&DlpAdaptor::ReplyOnCheckFilesTransfer,
                     base::Unretained(this), std::move(response)));

  auto cache_callback =
      base::BindOnce(&DlpRequestsCache::CacheResult,
                     base::Unretained(&requests_cache_), matching_request);

  dlp_files_policy_service_->IsFilesTransferRestrictedAsync(
      SerializeProto(matching_request),
      base::BindOnce(&DlpAdaptor::OnIsFilesTransferRestricted,
                     base::Unretained(this), std::move(files_to_check),
                     std::move(already_restricted), std::move(callbacks.first),
                     std::move(cache_callback)),
      base::BindOnce(&DlpAdaptor::OnIsFilesTransferRestrictedError,
                     base::Unretained(this), std::move(callbacks.second)),
      /*timeout_ms=*/base::Minutes(5).InMilliseconds());
}

void DlpAdaptor::OnIsFilesTransferRestricted(
    base::flat_set<std::string> checked_files,
    std::vector<std::string> restricted_files,
    CheckFilesTransferCallback callback,
    base::OnceCallback<void(IsFilesTransferRestrictedResponse)> cache_callback,
    const std::vector<uint8_t>& response_blob) {
  IsFilesTransferRestrictedResponse response;
  std::string parse_error = ParseProto(FROM_HERE, &response, response_blob);
  if (!parse_error.empty()) {
    LOG(ERROR) << "Failed to parse IsFilesTransferRestricted response: "
               << parse_error;
    dlp_metrics_->SendAdaptorError(AdaptorError::kInvalidProtoError);
    std::move(callback).Run(std::vector<std::string>(), parse_error);
    return;
  }

  // Cache the response.
  std::move(cache_callback).Run(response);
  for (const auto& file : response.files_restrictions()) {
    DCHECK(base::Contains(checked_files, file.file_metadata().path()));
    if (file.restriction_level() == ::dlp::RestrictionLevel::LEVEL_BLOCK ||
        file.restriction_level() ==
            ::dlp::RestrictionLevel::LEVEL_WARN_CANCEL) {
      restricted_files.push_back(file.file_metadata().path());
    }
  }

  std::move(callback).Run(std::move(restricted_files),
                          /*error_message=*/std::string());
}

void DlpAdaptor::OnIsFilesTransferRestrictedError(
    CheckFilesTransferCallback callback, brillo::Error* error) {
  LOG(ERROR) << "Failed to check which file should be restricted";
  dlp_metrics_->SendAdaptorError(AdaptorError::kRestrictionDetectionError);
  std::move(callback).Run(std::vector<std::string>(), error->GetMessage());
}

void DlpAdaptor::ReplyOnCheckFilesTransfer(
    std::unique_ptr<
        brillo::dbus_utils::DBusMethodResponse<std::vector<uint8_t>>> response,
    std::vector<std::string> restricted_files_paths,
    const std::string& error) {
  CheckFilesTransferResponse response_proto;
  *response_proto.mutable_files_paths() = {restricted_files_paths.begin(),
                                           restricted_files_paths.end()};
  if (!error.empty())
    response_proto.set_error_message(error);
  response->Return(SerializeProto(response_proto));
}

void DlpAdaptor::ProcessGetFilesSourcesWithData(
    std::unique_ptr<
        brillo::dbus_utils::DBusMethodResponse<std::vector<uint8_t>>> response,
    const std::vector<ino64_t>& requested_inodes,
    std::map<ino64_t, FileEntry> file_entries) {
  GetFilesSourcesResponse response_proto;
  for (const auto& inode : requested_inodes) {
    auto it = file_entries.find(inode);
    if (it == std::end(file_entries)) {
      continue;
    }
    FileMetadata* file_metadata = response_proto.add_files_metadata();
    file_metadata->set_inode(inode);
    file_metadata->set_source_url(it->second.source_url);
  }

  response->Return(SerializeProto(response_proto));
}

int DlpAdaptor::AddLifelineFd(int dbus_fd) {
  int fd = dup(dbus_fd);
  if (fd < 0) {
    PLOG(ERROR) << "dup failed";
    dlp_metrics_->SendAdaptorError(AdaptorError::kFileDescriptorDupError);
    return -1;
  }

  lifeline_fd_controllers_[fd] = base::FileDescriptorWatcher::WatchReadable(
      fd, base::BindRepeating(&DlpAdaptor::OnLifelineFdClosed,
                              base::Unretained(this), fd));

  return fd;
}

bool DlpAdaptor::DeleteLifelineFd(int fd) {
  auto iter = lifeline_fd_controllers_.find(fd);
  if (iter == lifeline_fd_controllers_.end()) {
    return false;
  }

  iter->second.reset();  // Destruct the controller, which removes the callback.
  lifeline_fd_controllers_.erase(iter);

  // AddLifelineFd() calls dup(), so this function should close the fd.
  // We still return true since at this point the FileDescriptorWatcher object
  // has been destructed.
  if (IGNORE_EINTR(close(fd)) < 0) {
    PLOG(ERROR) << "close failed";
    dlp_metrics_->SendAdaptorError(AdaptorError::kFileDescriptorCloseError);
  }

  return true;
}

void DlpAdaptor::OnLifelineFdClosed(int client_fd) {
  // The process that requested this access has died/exited.
  DeleteLifelineFd(client_fd);

  // Remove the approvals tied to the lifeline fd.
  approved_requests_.erase(client_fd);
}

// static
ino_t DlpAdaptor::GetInodeValue(const std::string& path) {
  struct stat file_stats;
  if (stat(path.c_str(), &file_stats) != 0) {
    PLOG(ERROR) << "Could not access " << path;
    return 0;
  }
  return file_stats.st_ino;
}

void DlpAdaptor::CleanupAndSetDatabase(
    std::unique_ptr<DlpDatabase> db,
    base::OnceClosure callback,
    const std::set<std::pair<base::FilePath, ino64_t>>& files) {
  DCHECK(db);
  DlpDatabase* db_ptr = db.get();

  std::set<ino64_t> inodes;
  for (const auto& entry : files) {
    inodes.insert(entry.second);
  }

  db_ptr->DeleteFileEntriesWithInodesNotInSet(
      inodes,
      base::BindOnce(&DlpAdaptor::OnDatabaseCleaned, base::Unretained(this),
                     std::move(db), std::move(callback)));
}

void DlpAdaptor::OnDatabaseCleaned(std::unique_ptr<DlpDatabase> db,
                                   base::OnceClosure callback,
                                   bool success) {
  if (success) {
    db_.swap(db);
    LOG(INFO) << "Database is initialized";
    // If fanotify watcher is already started, we need to add watches for all
    // files from the database.
    if (pending_per_file_watches_) {
      base::SingleThreadTaskRunner::GetCurrentDefault()
          ->PostTaskAndReplyWithResult(
              FROM_HERE, base::BindOnce(&EnumerateFiles, home_path_),
              base::BindOnce(&DlpAdaptor::AddPerFileWatch,
                             base::Unretained(this)));
      pending_per_file_watches_ = false;
    }
    std::move(callback).Run();
  }
}

}  // namespace dlp
