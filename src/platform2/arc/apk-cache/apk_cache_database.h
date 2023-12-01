// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_APK_CACHE_APK_CACHE_DATABASE_H_
#define ARC_APK_CACHE_APK_CACHE_DATABASE_H_

#include <stdint.h>

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/time/time.h>
#include <sqlite3.h>

namespace apk_cache {

// Database for opaque files support in ARC++ APK cache.
// Design doc: go/arc-apk-cache-opaque-files

// |Session| objects stored in |sessions| table.
// A session represents a file streaming session, which is used to avoid race
// condition between play store and cache cleaner. For example, while play store
// is streaming a file, cache cleaner will treat related file entry as invalid
// and delete it because of size mismatch. When play store wants to push a
// package, a session is created. The same session |id| is used through the
// whole streaming process. The session is marked as closed once the streaming
// process finishes. Cache cleaner will also create a session before cleaning,
// in case play store starts pushing packages during cleaning. |source| is used
// to indicate which component created the session. Sessions have maximum age
// limits. Expired sessions must be removed. |timestamp| stores creation time of
// the session. |status| is the status code of the session (open, closed, etc.).
struct Session {
  int64_t id;
  std::string source;
  base::Time timestamp;
  int32_t status;
};

// |FileEntry| objects stored in |file_entries| table.
// A file entry represents a file (base APK or other types) stored in APK cache.
// |id| is used to uniquely identify them. Physical files stored on the disk are
// named with their |id| in hexadecimal. |package_name| and |version_code|
// represent which specific package is the file in. |type| represents what type
// the file is. This is managed by play store. Every package must contain only
// one file of type base APK. Other types are not restricted. |attributes| is
// used to store additional info about the file, for example OBB version. |size|
// is size of the file, this must match physical file on the disk. |hash| is
// SHA-256 digest encoded in Base64, which is the same hashing method as play
// store. |access_time| stored access time of the file. |priority| is cache
// priority of the package. |session_id| is a foreign key to |Session.id|, which
// represents the session the file entry is from.
struct FileEntry {
  int64_t id;
  std::string package_name;
  int64_t version_code;
  std::string type;
  std::optional<std::string> attributes;
  int64_t size;
  std::optional<std::string> hash;
  base::Time access_time;
  int32_t priority;
  int64_t session_id;
};

// Escapes string in SQL. Replaces ' with ''.
std::string EscapeSQLString(const std::string& string_to_escape);

// Provides access to APK cache database.
class ApkCacheDatabase {
 public:
  // Creates an instance to talk to the database file at |db_path|. Init() must
  // be called to establish connection.
  explicit ApkCacheDatabase(const base::FilePath& db_path);

  // Not copyable or movable.
  ApkCacheDatabase(const ApkCacheDatabase&) = delete;
  ApkCacheDatabase& operator=(const ApkCacheDatabase&) = delete;

  ~ApkCacheDatabase();

  // Initializes database connection. Must be called before any other queries.
  // Returns |SQLITE_OK| if no error ocurred.
  int Init();
  // Returns true if the database connection is open.
  bool IsOpen();
  // Closes database connection. Returns |SQLITE_OK| if no error occurred.
  // Otherwise SQLite error code is returned.
  int Close();
  // Runs SQLite built-in integrity check. Returns true if no error is found.
  bool CheckIntegrity() const;
  // Returns true if sessions table exists.
  bool SessionsTableExists() const;
  // Inserts session into database. Returns |id|. Returns 0 if error occurred.
  int64_t InsertSession(const Session& session) const;
  // Gets all sessions. Returns nullopt if any error occurs.
  std::optional<std::vector<Session>> GetSessions() const;
  // Gets all file entries. Returns nullopt if any error occurs.
  std::optional<std::vector<FileEntry>> GetFileEntries() const;
  // Deletes |session| from database. Any file entries referencing this session
  // will also be removed. Returns true if no error occurred.
  bool DeleteSession(int64_t session_id) const;
  // Deletes sessions without any file entries. Do not delete |current_session|.
  // Returns number of rows affected. Returns -1 if error occurred.
  int DeleteSessionsWithoutFileEntries(int64_t current_session) const;
  // Deletes |file_entry| from database. Returns true if no error occurred.
  bool DeleteFileEntry(int64_t file_id) const;
  // Deletes all file entries in a package. Returns number of rows affected.
  // Returns -1 if error occurred
  int DeletePackage(const std::string& name, int64_t version) const;
  // Updates session status. Returns true if successful.
  bool UpdateSessionStatus(int64_t id, int32_t status) const;

 private:
  using SqliteCallback = int (*)(void*, int, char**, char**);

  struct ExecResult {
    int code;
    std::string error_msg;
  };

  // Enables foreign key support in SQLite library. By default foreign key is
  // not enabled, which results in foreign key constraints not being checked
  // during insert, update and delete.
  int EnableForeignKey() const;
  // Execute SQL.
  ExecResult ExecSQL(const std::string& sql) const;
  ExecResult ExecSQL(const std::string& sql,
                     SqliteCallback callback,
                     void* data) const;
  // Executes SQL that deletes rows. Returns number of rows affected. Returns -1
  // if error occurs.
  int ExecDeleteSQL(const std::string& sql) const;

  base::FilePath db_path_;
  std::unique_ptr<sqlite3, decltype(&sqlite3_close)> db_;
};

}  // namespace apk_cache

#endif  // ARC_APK_CACHE_APK_CACHE_DATABASE_H_
