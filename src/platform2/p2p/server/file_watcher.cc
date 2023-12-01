// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "p2p/server/file_watcher.h"

#include <gio/gio.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>

#include <base/logging.h>

using std::string;
using std::vector;

using base::FilePath;

namespace p2p {

namespace server {

class FileWatcherGLib : public FileWatcher {
 public:
  FileWatcherGLib(const FilePath& dir, const string& file_extension);
  FileWatcherGLib(const FileWatcherGLib&) = delete;
  FileWatcherGLib& operator=(const FileWatcherGLib&) = delete;

  ~FileWatcherGLib() override;

  const vector<FilePath>& files() const override;

  const FilePath& dir() const override;
  const string& file_extension() const override;

  void SetChangedCallback(FileWatcherCallback changed_callback) override;

  bool Init();

 private:
  // Looks at all files in |dir_| and sees if anything has
  // changed. Usually called from the file monitoring callback from
  // the kernel (inotify via GFileMonitor). The |changed_file|
  // parameter should be NULL unless the kernel indicates the given
  // file has changed. Updates the |files_| member.
  void ReloadDir(const FilePath* changed_file);

  // Used for handling the GFileMonitor::changed GLib signal.
  static void OnMonitorChanged(GFileMonitor* monitor,
                               GFile* file,
                               GFile* other_file,
                               GFileMonitorEvent event_type,
                               gpointer user_data);

  // The directory we monitor.
  FilePath dir_;

  // The file extension for files we are interested in, e.g. ".p2p".
  string file_extension_;

  // The callback set by the user of our callback.
  FileWatcherCallback changed_callback_;

  // The current set of files in |dir_|. Is updated by ReloadDir().
  vector<FilePath> files_;

  // The GLib abstraction used to interface with the kernel's inotify
  // subsystem.
  GFileMonitor* monitor_;
};

const FilePath& FileWatcherGLib::dir() const {
  return dir_;
}

const string& FileWatcherGLib::file_extension() const {
  return file_extension_;
}

void FileWatcherGLib::OnMonitorChanged(GFileMonitor* monitor,
                                       GFile* file,
                                       GFile* other_file,
                                       GFileMonitorEvent event_type,
                                       gpointer user_data) {
  FileWatcherGLib* file_watcher = reinterpret_cast<FileWatcherGLib*>(user_data);

  // Ignore hints
  if (event_type == G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT)
    return;

  // Ignore files not matching the extension
  gchar* file_name = g_file_get_path(file);
  if (!g_str_has_suffix(file_name, file_watcher->file_extension_.c_str())) {
    g_free(file_name);
    return;
  }

  VLOG(2) << "OnMonitorChanged, event_type=" << event_type
          << " file=" << file_name;
  FilePath path(file_name);
  file_watcher->ReloadDir(&path);
  g_free(file_name);
}

FileWatcherGLib::FileWatcherGLib(const FilePath& dir,
                                 const string& file_extension)
    : dir_(dir), file_extension_(file_extension) {}

bool FileWatcherGLib::Init() {
  GFile* file;
  GError* error = NULL;

  file = g_file_new_for_path(dir_.value().c_str());
  monitor_ = g_file_monitor_directory(file, G_FILE_MONITOR_NONE,
                                      NULL, /* GCancellable */
                                      &error);
  if (monitor_ == NULL) {
    LOG(ERROR) << "Error monitoring directory " << dir_.value() << ": "
               << error->message << "(" << error->code << ", "
               << g_quark_to_string(error->domain) << ")";
    g_clear_error(&error);
    return false;
  } else {
    g_signal_connect(monitor_, "changed", G_CALLBACK(OnMonitorChanged), this);
  }

  ReloadDir(NULL);

  g_clear_object(&file);
  return true;
}

FileWatcherGLib::~FileWatcherGLib() {
  if (monitor_ != NULL) {
    g_signal_handlers_disconnect_by_func(monitor_, (gpointer)OnMonitorChanged,
                                         this);
    g_file_monitor_cancel(monitor_);
    g_clear_object(&monitor_);
  }
}

void FileWatcherGLib::SetChangedCallback(FileWatcherCallback changed_callback) {
  changed_callback_ = changed_callback;
}

static void diff_sorted_vectors(
    const vector<FilePath>::iterator& a_first,
    const vector<FilePath>::iterator& a_last,
    const vector<FilePath>::iterator& b_first,
    const vector<FilePath>::iterator& b_last,
    vector<FilePath>* added,        // in b, not in a
    vector<FilePath>* removed,      // in a, not in b
    vector<FilePath>* unchanged) {  // in both a and b
  vector<FilePath>::const_iterator ai = a_first;
  vector<FilePath>::const_iterator bi = b_first;

  while (ai != a_last && bi != b_last) {
    int order = ai->value().compare(bi->value());
    if (order < 0) {
      // *ai > *bi
      removed->push_back(*ai);
      ++ai;
    } else if (order > 0) {
      // *ai < *bi
      added->push_back(*bi);
      ++bi;
    } else {
      // *ai == *bi
      unchanged->push_back(*bi);
      ++ai;
      ++bi;
    }
  }

  while (ai != a_last) {
    removed->push_back(*ai);
    ++ai;
  }

  while (bi != b_last) {
    added->push_back(*bi);
    ++bi;
  }
}

void FileWatcherGLib::ReloadDir(const FilePath* changed_file) {
  GDir* dir;
  GError* error = NULL;
  const char* name;
  vector<FilePath> new_files;

  VLOG(2) << "in ReloadDir(), dir=" << dir_.value() << "file="
          << (changed_file != NULL ? changed_file->value() : "(none)");

  dir = g_dir_open(dir_.value().c_str(), 0, &error);
  if (dir == NULL) {
    LOG(ERROR) << "Error opening directory " << dir_.value() << ": "
               << error->message << "(" << error->code << ", "
               << g_quark_to_string(error->domain) << ")";
    return;
  }

  while ((name = g_dir_read_name(dir)) != NULL) {
    if (file_extension_.length() > 0 &&
        g_str_has_suffix(name, file_extension_.c_str())) {
      new_files.push_back(dir_.Append(name));
    }
  }
  g_dir_close(dir);

  vector<FilePath> added;
  vector<FilePath> removed;
  vector<FilePath> unchanged;
  std::sort(new_files.begin(), new_files.end());
  // TODO(zeuthen): actually unnecessary to sort files_
  std::sort(files_.begin(), files_.end());
  diff_sorted_vectors(files_.begin(), files_.end(), new_files.begin(),
                      new_files.end(), &added, &removed, &unchanged);
  files_ = new_files;

  if (!changed_callback_.is_null()) {
    for (auto const& i : removed) {
      VLOG(2) << "Emitting kFileRemoved for file " << i.value();
      changed_callback_.Run(i, FileWatcher::EventType::kFileRemoved);
    }
    for (auto const& i : unchanged) {
      if (changed_file != NULL && *changed_file == i) {
        VLOG(2) << "Emitting kFileChanged for file " << i.value();
        changed_callback_.Run(i, FileWatcher::EventType::kFileChanged);
      }
    }
    for (auto const& i : added) {
      VLOG(2) << "Emitting kFileAdded for file " << i.value();
      changed_callback_.Run(i, FileWatcher::EventType::kFileAdded);
    }
  }
}

const vector<FilePath>& FileWatcherGLib::files() const {
  return files_;
}

// -----------------------------------------------------------------------------

FileWatcher* FileWatcher::Construct(const FilePath& dir,
                                    const string& file_extension) {
  FileWatcherGLib* instance = new FileWatcherGLib(dir, file_extension);
  if (!instance->Init()) {
    delete instance;
    return NULL;
  }
  return instance;
}

}  // namespace server

}  // namespace p2p
