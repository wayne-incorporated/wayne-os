// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLP_DLP_ADAPTOR_H_
#define DLP_DLP_ADAPTOR_H_

#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/containers/flat_set.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/scoped_file.h>
#include <base/functional/callback.h>
#include <brillo/dbus/async_event_sequencer.h>
#include <featured/feature_library.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "dlp/dbus-proxies.h"
#include "dlp/dlp_database.h"
#include "dlp/dlp_metrics.h"
#include "dlp/dlp_requests_cache.h"
#include "dlp/fanotify_watcher.h"
#include "dlp/org.chromium.Dlp.h"
#include "dlp/proto_bindings/dlp_service.pb.h"

namespace brillo {
namespace dbus_utils {
class DBusObject;
}  // namespace dbus_utils
}  // namespace brillo

namespace dlp {

class DlpAdaptor : public org::chromium::DlpAdaptor,
                   public org::chromium::DlpInterface,
                   public FanotifyWatcher::Delegate,
                   public DlpDatabase::Delegate {
 public:
  DlpAdaptor(std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object,
             feature::PlatformFeaturesInterface* feature_lib,
             int fanotify_perm_fd,
             int fanotify_notif_fd,
             const base::FilePath& home_path);
  DlpAdaptor(const DlpAdaptor&) = delete;
  DlpAdaptor& operator=(const DlpAdaptor&) = delete;
  virtual ~DlpAdaptor();

  // Opens the database |db_| to store files sources, |init_callback| called
  // after the database is set.
  void InitDatabase(const base::FilePath& database_path,
                    base::OnceClosure init_callback);

  // Registers the D-Bus object and interfaces.
  void RegisterAsync(brillo::dbus_utils::AsyncEventSequencer::CompletionAction
                         completion_callback);

  // org::chromium::DlpInterface: (see org.chromium.Dlp.xml).
  std::vector<uint8_t> SetDlpFilesPolicy(
      const std::vector<uint8_t>& request_blob) override;
  // TODO(b/286202080): Remove once client code use AddFiles.
  void AddFile(std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                   std::vector<uint8_t>>> response,
               const std::vector<uint8_t>& request_blob) override;
  void AddFiles(std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                    std::vector<uint8_t>>> response,
                const std::vector<uint8_t>& request_blob) override;
  void RequestFileAccess(
      std::unique_ptr<
          brillo::dbus_utils::DBusMethodResponse<std::vector<uint8_t>,
                                                 base::ScopedFD>> response,
      const std::vector<uint8_t>& request_blob) override;
  void GetFilesSources(std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                           std::vector<uint8_t>>> response,
                       const std::vector<uint8_t>& request_blob) override;
  void CheckFilesTransfer(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          std::vector<uint8_t>>> response,
      const std::vector<uint8_t>& request_blob) override;

  void SetFanotifyWatcherStartedForTesting(bool is_started);
  void CloseDatabaseForTesting();

 private:
  friend class DlpAdaptorTest;
  FRIEND_TEST(DlpAdaptorTest, AllowedWithoutDatabase);
  FRIEND_TEST(DlpAdaptorTest, AllowedWithDatabase);
  FRIEND_TEST(DlpAdaptorTest, NotRestrictedFileAddedAndAllowed);
  FRIEND_TEST(DlpAdaptorTest, RestrictedFileAddedAndNotAllowed);
  FRIEND_TEST(DlpAdaptorTest, RestrictedFileAddedAndRequestedAllowed);
  FRIEND_TEST(DlpAdaptorTest, RestrictedFilesNotAddedAndRequestedAllowed);
  FRIEND_TEST(DlpAdaptorTest, RestrictedFileNotAddedAndImmediatelyAllowed);
  FRIEND_TEST(DlpAdaptorTest, RestrictedFileAddedAndRequestedNotAllowed);
  FRIEND_TEST(DlpAdaptorTest,
              RestrictedFileAddedRequestedAndCancelledNotAllowed);
  FRIEND_TEST(DlpAdaptorTest, RequestAllowedWithoutDatabase);
  FRIEND_TEST(DlpAdaptorTest, GetFilesSources);
  FRIEND_TEST(DlpAdaptorTest, GetFilesSourcesWithoutDatabase);
  FRIEND_TEST(DlpAdaptorTest, GetFilesSourcesFileDeletedDBReopenedWithCleanup);
  FRIEND_TEST(DlpAdaptorTest,
              GetFilesSourcesFileDeletedDBReopenedWithoutCleanup);
  FRIEND_TEST(DlpAdaptorTest, GetFilesSourcesFileDeletedInFlight);
  FRIEND_TEST(DlpAdaptorTest, SetDlpFilesPolicy);
  FRIEND_TEST(DlpAdaptorTest, CheckFilesTransfer);
  FRIEND_TEST(DlpAdaptorTest, RestrictedFileAddedAndRequestedCachedAllowed);
  FRIEND_TEST(DlpAdaptorTest, RestrictedFileAddedAndRequestedCachedNotAllowed);

  // Callback on InitDatabase after initialization of the database.
  void OnDatabaseInitialized(base::OnceClosure init_callback,
                             std::unique_ptr<DlpDatabase> db,
                             const base::FilePath& database_path,
                             int db_status);

  // Callback on InsertFileEntries during OnDatabaseInitialized.
  void OnPendingFilesInserted(base::OnceClosure init_callback,
                              std::unique_ptr<DlpDatabase> db,
                              const base::FilePath& database_path,
                              int db_status,
                              bool success);

  // Initializes |fanotify_watcher_| if not yet started.
  void EnsureFanotifyWatcherStarted();

  // FanotifyWatcher::Delegate overrides:
  void ProcessFileOpenRequest(ino_t inode,
                              int pid,
                              base::OnceCallback<void(bool)> callback) override;
  void OnFileDeleted(ino_t inode) override;

  void OnFanotifyError(FanotifyError error) override;

  // DlpDatabase::Delegate overrides:
  void OnDatabaseError(DatabaseError error) override;

  // Callback on ProcessFileOpenRequest after getting data from database.
  void ProcessFileOpenRequestWithData(int pid,
                                      base::OnceCallback<void(bool)> callback,
                                      std::map<ino64_t, FileEntry> file_entry);

  // Callbacks on DlpPolicyMatched D-Bus request for ProcessFileOpenRequest.
  void OnDlpPolicyMatched(base::OnceCallback<void(bool)> callback,
                          const std::vector<uint8_t>& response_blob);
  void OnDlpPolicyMatchedError(base::OnceCallback<void(bool)> callback,
                               brillo::Error* error);

  // Callback for RequestFileAccess after getting data from the database.
  void ProcessRequestFileAccessWithData(
      std::unique_ptr<
          brillo::dbus_utils::DBusMethodResponse<std::vector<uint8_t>,
                                                 base::ScopedFD>> response,
      RequestFileAccessRequest request,
      base::ScopedFD local_fd,
      base::ScopedFD remote_fd,
      std::map<ino64_t, FileEntry> file_entries);

  using RequestFileAccessCallback =
      base::OnceCallback<void(bool, const std::string&)>;
  // Callbacks on IsFilesTransferRestricted D-Bus request for RequestFileAccess.
  void OnRequestFileAccess(
      std::vector<uint64_t> inodes,
      std::vector<uint64_t> granted_inodes,
      int pid,
      base::ScopedFD local_fd,
      RequestFileAccessCallback callback,
      base::OnceCallback<void(IsFilesTransferRestrictedResponse)>
          cache_callback,
      const std::vector<uint8_t>& response_blob);
  void OnRequestFileAccessError(RequestFileAccessCallback callback,
                                brillo::Error* error);
  void ReplyOnRequestFileAccess(
      std::unique_ptr<
          brillo::dbus_utils::DBusMethodResponse<std::vector<uint8_t>,
                                                 base::ScopedFD>> response,
      base::ScopedFD remote_fd,
      bool allowed,
      const std::string& error_message);

  // Callback on AddFile after adding to the database.
  // TODO(b/286202080): Remove once client code use AddFiles.
  void OnFileInserted(std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                          std::vector<uint8_t>>> response,
                      const std::string& file_path,
                      ino_t inode,
                      bool success);
  // Callback on AddFiles after adding to the database.
  void OnFilesInserted(std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                           std::vector<uint8_t>>> response,
                       std::vector<base::FilePath> files_paths,
                       std::vector<ino_t> files_inodes,
                       bool success);
  // Helper to reply on AddFile request.
  // TODO(b/286202080): Remove once client code use AddFiles.
  void ReplyOnAddFile(std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                          std::vector<uint8_t>>> response,
                      std::string error_message);
  // Helper to reply on AddFiles request.
  void ReplyOnAddFiles(std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                           std::vector<uint8_t>>> response,
                       std::string error_messages);
  // Callback for CheckFilesTransfer after getting data from the database.
  void ProcessCheckFilesTransferWithData(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          std::vector<uint8_t>>> response,
      CheckFilesTransferRequest request,
      std::map<ino64_t, FileEntry> file_entries);

  using CheckFilesTransferCallback =
      base::OnceCallback<void(std::vector<std::string>, const std::string&)>;
  // Callback on IsFilesTransferRestricted D-Bus request for CheckFilesTransfer.
  void OnIsFilesTransferRestricted(
      base::flat_set<std::string> transferred_files,
      std::vector<std::string> restricted_files,
      CheckFilesTransferCallback callback,
      base::OnceCallback<void(IsFilesTransferRestrictedResponse)>
          cache_callback,
      const std::vector<uint8_t>& response_blob);
  void OnIsFilesTransferRestrictedError(CheckFilesTransferCallback callback,
                                        brillo::Error* error);
  void ReplyOnCheckFilesTransfer(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          std::vector<uint8_t>>> response,
      std::vector<std::string> restricted_files_paths,
      const std::string& error);

  // Callback on GetFilesSources after getting data from database.
  void ProcessGetFilesSourcesWithData(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          std::vector<uint8_t>>> response,
      const std::vector<ino64_t>& requested_inodes,
      std::map<ino64_t, FileEntry> file_entries);

  // Functions and callbacks to handle lifeline fd.
  int AddLifelineFd(int dbus_fd);
  bool DeleteLifelineFd(int fd);
  void OnLifelineFdClosed(int fd);

  static ino_t GetInodeValue(const std::string& path);

  // Removes entries from |db| that are not present in |inodes| and sets the
  // used database to |db|. |callback| is called if this successfully finishes.
  void CleanupAndSetDatabase(
      std::unique_ptr<DlpDatabase> db,
      base::OnceClosure callback,
      const std::set<std::pair<base::FilePath, ino64_t>>& inodes);

  // Requests fanotify to add per-file watch (FAN_DELETE_SELF event) for each
  // of the provided files if they exist in the database.
  void AddPerFileWatch(
      const std::set<std::pair<base::FilePath, ino64_t>>& files);
  // Callback on AddPerFileWatch after recieving the list of tracked files.
  void ProcessAddPerFileWatchWithData(
      const std::set<std::pair<base::FilePath, ino64_t>>& files,
      std::map<ino64_t, FileEntry> file_entries);

  // Callback on CleanupAndSetDatabase after removing data from database.
  void OnDatabaseCleaned(std::unique_ptr<DlpDatabase> db,
                         base::OnceClosure callback,
                         bool success);

  // If true, DlpAdaptor won't try to initialise `fanotify_watcher_`.
  bool is_fanotify_watcher_started_for_testing_ = false;

  // Can be nullptr if failed to initialize or closed during a test.
  std::unique_ptr<DlpDatabase> db_;

  std::vector<DlpFilesRule> policy_rules_;

  std::unique_ptr<FanotifyWatcher> fanotify_watcher_;

  std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object_;

  feature::PlatformFeaturesInterface* feature_lib_ = nullptr;

  // Cache of IsFilesTransferRestricted replies from Chrome.
  DlpRequestsCache requests_cache_;

  // The root path to the watched directory.
  const base::FilePath home_path_;

  std::unique_ptr<org::chromium::DlpFilesPolicyServiceProxy>
      dlp_files_policy_service_;

  std::unique_ptr<DlpMetrics> dlp_metrics_;

  // Map holding the currently approved access requests.
  // Maps from the lifeline fd to a pair of list of files inodes and pid.
  std::map<int, std::pair<std::vector<uint64_t>, int>> approved_requests_;

  // Map holding watchers for lifeline fd corresponding currently approved
  // requests. Maps from the lifeline fd to the watcher.
  std::map<int, std::unique_ptr<base::FileDescriptorWatcher::Controller>>
      lifeline_fd_controllers_;

  // Indicated whether adding per file watch for files in the database is
  // pending creation of the database.
  bool pending_per_file_watches_ = false;

  // Files that were added before database was initialized, so they need to be
  // added once it's ready.
  std::vector<FileEntry> pending_files_to_add_;
};

}  // namespace dlp

#endif  // DLP_DLP_ADAPTOR_H_
