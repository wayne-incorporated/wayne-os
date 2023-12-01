// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_GARCON_DESKTOP_FILE_H_
#define VM_TOOLS_GARCON_DESKTOP_FILE_H_

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>

namespace vm_tools {
namespace garcon {
// Parses .desktop files according to the Desktop Entry Specification here:
// https://standards.freedesktop.org/desktop-entry-spec/desktop-entry-spec-1.2.html
class DesktopFile {
 public:
  // Returns empty unique_ptr if there was a failure parsing the .desktop file.
  static std::unique_ptr<DesktopFile> ParseDesktopFile(
      const base::FilePath& file_path);
  ~DesktopFile() = default;

  // Gets the list of paths where .desktop files can reside under. Each path
  // returned from this will have "applications" as the last path component.
  static std::vector<base::FilePath> GetPathsForDesktopFiles();

  // Searches for the corresponding .desktop file which correlates to the passed
  // in |desktop_id|. This follows the rules of the spec for searching and in
  // addition to that, if there is no XDG_DATA_DIRS env variable, then it will
  // just search in /usr/share/applications/.  If no such file can be found this
  // will return an empty file path.
  static base::FilePath FindFileForDesktopId(const std::string& desktop_id);

  // Generates an argv list that can be used for executing the program
  // associated with this desktop file. The returned vector will be empty if
  // there are any issues with the Exec key or it didn't exist. It also handles
  // the case where we need to pass one or more filenames or URLs for a
  // parameter. If Exec doesn't handle file/URL args, then |app_args| will be
  // ignored; if it only handles one file/URL then only the first in the list
  // will be used. It is valid for |app_args| to be empty if there are no
  // files/URLs to pass as args.
  std::vector<std::string> GenerateArgvWithFiles(
      const std::vector<std::string>& app_args) const;

  // Uses GenerateArgvWithFiles to parse and return the exec name of a desktop
  // file
  std::string GenerateExecutableFileName() const;

  // Returns true if this .desktop file is one that should be sent to the host.
  // There are various rules contained in here that determine what files should
  // actually be passed along.
  bool ShouldPassToHost() const;

  const std::string& app_id() const { return app_id_; }
  const std::string& entry_type() const { return entry_type_; }
  const std::map<std::string, std::string>& locale_name_map() const {
    return locale_name_map_;
  }
  const std::map<std::string, std::string>& locale_comment_map() const {
    return locale_comment_map_;
  }
  const std::map<std::string, std::vector<std::string>>& locale_keywords_map()
      const {
    return locale_keywords_map_;
  }
  bool no_display() const { return no_display_; }
  const std::string& icon() { return icon_; }
  bool hidden() const { return hidden_; }
  const std::vector<std::string>& only_show_in() const { return only_show_in_; }
  const std::vector<std::string>& not_show_in() const { return not_show_in_; }
  const std::string& try_exec() const { return try_exec_; }
  const std::string& exec() const { return exec_; }
  const std::string& path() const { return path_; }
  bool terminal() const { return terminal_; }
  const std::vector<std::string>& mime_types() const { return mime_types_; }
  const std::vector<std::string>& categories() const { return categories_; }
  const std::string& startup_wm_class() const { return startup_wm_class_; }
  bool startup_notify() const { return startup_notify_; }
  // This returns the path to the parsed .desktop file itself.
  const base::FilePath& file_path() const { return file_path_; }
  const uint64_t steam_app_id() const { return steam_app_id_; }

  // Returns true if this desktop file is of type "Application".
  bool IsApplication() const;

 private:
  DesktopFile() = default;
  DesktopFile(const DesktopFile&) = delete;
  DesktopFile& operator=(const DesktopFile&) = delete;

  bool LoadFromFile(const base::FilePath& file_path);

  base::FilePath file_path_;
  std::string app_id_;
  std::string entry_type_;
  std::map<std::string, std::string> locale_name_map_;
  std::map<std::string, std::string> locale_comment_map_;
  std::map<std::string, std::vector<std::string>> locale_keywords_map_;
  bool no_display_ = false;
  std::string icon_;
  bool hidden_ = false;
  std::vector<std::string> only_show_in_;
  std::vector<std::string> not_show_in_;
  std::string try_exec_;
  std::string exec_;
  std::string path_;
  bool terminal_ = false;
  std::vector<std::string> mime_types_;
  std::vector<std::string> categories_;
  std::string startup_wm_class_;
  bool startup_notify_ = false;
  uint64_t steam_app_id_ = 0;
};

}  // namespace garcon
}  // namespace vm_tools

#endif  // VM_TOOLS_GARCON_DESKTOP_FILE_H_
