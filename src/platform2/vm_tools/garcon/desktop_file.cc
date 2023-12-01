// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdlib.h>

#include <algorithm>
#include <memory>
#include <utility>

#include <base/environment.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>

#include "vm_tools/garcon/desktop_file.h"
#include "vm_tools/garcon/ini_parse_util.h"
#include "vm_tools/garcon/xdg_util.h"

namespace {
constexpr int kMaxHyphensAllowed = 10;
// Ridiculously large size for a desktop file.
constexpr size_t kMaxDesktopFileSize = 10485760;  // 10 MB
// Group name for the main entry we want.
constexpr char kDesktopEntryGroupName[] = "Desktop Entry";
// File extension for desktop files.
constexpr char kDesktopFileExtension[] = ".desktop";
// Desktop path start delimiter for constructing application IDs.
constexpr char kDesktopPathStartDelimiter[] = "applications";
// Key names for the fields we care about.
constexpr char kDesktopEntryType[] = "Type";
constexpr char kDesktopEntryName[] = "Name";
constexpr char kDesktopEntryNameWithLocale[] = "Name[";
constexpr char kDesktopEntryNoDisplay[] = "NoDisplay";
constexpr char kDesktopEntryComment[] = "Comment";
constexpr char kDesktopEntryCommentWithLocale[] = "Comment[";
constexpr char kDesktopEntryIcon[] = "Icon";
constexpr char kDesktopEntryHidden[] = "Hidden";
constexpr char kDesktopEntryOnlyShowIn[] = "OnlyShowIn";
constexpr char kDesktopEntryNotShowIn[] = "NotShowIn";
constexpr char kDesktopEntryTryExec[] = "TryExec";
constexpr char kDesktopEntryExec[] = "Exec";
constexpr char kDesktopEntryPath[] = "Path";
constexpr char kDesktopEntryTerminal[] = "Terminal";
constexpr char kDesktopEntryMimeType[] = "MimeType";
constexpr char kDesktopEntryKeywords[] = "Keywords";
constexpr char kDesktopEntryKeywordsWithLocale[] = "Keywords[";
constexpr char kDesktopEntryCategories[] = "Categories";
constexpr char kDesktopEntryStartupWmClass[] = "StartupWMClass";
constexpr char kDesktopEntryStartupNotify[] = "StartupNotify";
constexpr char kDesktopEntryTypeApplication[] = "Application";
constexpr char kDesktopEntrySteamAppId[] = "X-Steam-AppID";
// Valid values for the "Type" entry.
const char* const kValidDesktopEntryTypes[] = {kDesktopEntryTypeApplication,
                                               "Link", "Directory"};
constexpr char kSettingsCategory[] = "Settings";
constexpr char kPathEnvVar[] = "PATH";
// For the purpose of determining apps relevant to our desktop env, pretend we
// are a gnome desktop. See crbug.com/839132 for details.
constexpr char kDesktopType[] = "GNOME";

}  // namespace

namespace vm_tools {
namespace garcon {

// static
std::unique_ptr<DesktopFile> DesktopFile::ParseDesktopFile(
    const base::FilePath& file_path) {
  std::unique_ptr<DesktopFile> retval(new DesktopFile());
  if (!retval->LoadFromFile(file_path)) {
    retval.reset();
  }
  return retval;
}

// static
std::vector<base::FilePath> DesktopFile::GetPathsForDesktopFiles() {
  std::vector<base::FilePath> data_dirs = xdg::GetDataDirectories();
  std::transform(data_dirs.begin(), data_dirs.end(), data_dirs.begin(),
                 [](const base::FilePath& path) {
                   return path.Append(kDesktopPathStartDelimiter);
                 });
  return data_dirs;
}

// static
base::FilePath DesktopFile::FindFileForDesktopId(
    const std::string& desktop_id) {
  if (desktop_id.empty()) {
    return base::FilePath();
  }

  // Check whether we should have a path separator for all possible positions of
  // the hyphens. (ref: b/243139102)
  uint32_t hyphen_count = 1;
  std::vector<int> hyphen_index;
  std::string mutable_desktop_id;
  base::ReplaceChars(desktop_id, "-", "/", &mutable_desktop_id);
  for (int i = 0; i < desktop_id.size(); i++) {
    if (desktop_id[i] == '-') {
      hyphen_count = hyphen_count << 1;
      hyphen_index.push_back(i);
    }
  }

  // If there are actually more than 32 path separators and hyphens it'd take
  // way too long, reverting to two candidate approach.
  if (hyphen_index.size() > kMaxHyphensAllowed) {
    std::string rel_path1;
    base::ReplaceChars(desktop_id, "-", "/", &rel_path1);
    rel_path1 += kDesktopFileExtension;
    std::string rel_paths[] = {rel_path1, desktop_id + kDesktopFileExtension};

    std::vector<base::FilePath> search_paths = GetPathsForDesktopFiles();
    for (const auto& curr_path : search_paths) {
      for (const auto& rel_path : rel_paths) {
        base::FilePath test_path(curr_path.Append(rel_path));
        if (base::PathExists(test_path))
          return test_path;
      }
    }
    return base::FilePath();
  }

  std::vector<base::FilePath> search_paths = GetPathsForDesktopFiles();
  // Check the base case
  for (uint32_t i = 0; i < hyphen_count; i++) {
    uint32_t bitmask = i;
    int hyphen_end = hyphen_index.size() - 1;
    for (int pos = hyphen_end; bitmask > 0 && pos >= 0; --pos) {
      if ((bitmask & 1) == 1) {
        // Replace with hyphen.
        mutable_desktop_id[hyphen_index[pos]] = '-';
      } else {
        // Only things that have been flipped before needs flipping.
        mutable_desktop_id[hyphen_index[pos]] = '/';
      }
      bitmask >>= 1;
    }
    for (const auto& curr_path : search_paths) {
      base::FilePath test_path(
          curr_path.Append(mutable_desktop_id + kDesktopFileExtension));
      if (base::PathExists(test_path))
        return test_path;
    }
  }
  return base::FilePath();
}

bool DesktopFile::LoadFromFile(const base::FilePath& file_path) {
  // First read in the file as a string.
  std::string desktop_contents;
  if (!ReadFileToStringWithMaxSize(file_path, &desktop_contents,
                                   kMaxDesktopFileSize)) {
    LOG(ERROR) << "Failed reading in desktop file: " << file_path.value();
    return false;
  }
  file_path_ = file_path;

  std::vector<base::StringPiece> desktop_lines = base::SplitStringPiece(
      desktop_contents, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  // Go through the file line by line, we are looking for the section marked:
  // [Desktop Entry]
  bool in_entry = false;
  for (const auto& curr_line : desktop_lines) {
    if (curr_line.front() == '#') {
      // Skip comment lines.
      continue;
    }
    if (curr_line.front() == '[') {
      if (in_entry) {
        // We only care about the main entry, so terminate parsing if we have
        // found it.
        break;
      }
      // Group name.
      base::StringPiece group_name = ParseGroupName(curr_line);
      if (group_name.empty()) {
        continue;
      }
      if (group_name == kDesktopEntryGroupName) {
        in_entry = true;
      }
    } else if (!in_entry) {
      // We are not in the main entry, and this line doesn't begin that entry so
      // skip it.
      continue;
    } else {
      // Parse the key/value pair on this line for the desktop entry.
      std::pair<std::string, std::string> key_value =
          ExtractKeyValuePair(curr_line);
      if (key_value.second.empty()) {
        // Invalid key/value pair since there was no delimiter, skip this line.
        continue;
      }
      // Check for matching names against all the keys. For the ones that can
      // have a locale in the key name, do those last since we do a startsWith
      // comparison on those.
      std::string key = key_value.first;
      if (key == kDesktopEntryType) {
        entry_type_ = key_value.second;
      } else if (key == kDesktopEntryName) {
        locale_name_map_[""] = UnescapeString(key_value.second);
      } else if (key == kDesktopEntryNoDisplay) {
        no_display_ = ParseBool(key_value.second);
      } else if (key == kDesktopEntryComment) {
        locale_comment_map_[""] = UnescapeString(key_value.second);
      } else if (key == kDesktopEntryIcon) {
        icon_ = key_value.second;
      } else if (key == kDesktopEntryHidden) {
        hidden_ = ParseBool(key_value.second);
      } else if (key == kDesktopEntryOnlyShowIn) {
        ParseMultiString(key_value.second, &only_show_in_);
      } else if (key == kDesktopEntryNotShowIn) {
        ParseMultiString(key_value.second, &not_show_in_);
      } else if (key == kDesktopEntryTryExec) {
        try_exec_ = UnescapeString(key_value.second);
      } else if (key == kDesktopEntryExec) {
        exec_ = UnescapeString(key_value.second);
      } else if (key == kDesktopEntryPath) {
        path_ = UnescapeString(key_value.second);
      } else if (key == kDesktopEntryTerminal) {
        terminal_ = ParseBool(key_value.second);
      } else if (key == kDesktopEntryMimeType) {
        ParseMultiString(key_value.second, &mime_types_);
      } else if (key == kDesktopEntryKeywords) {
        ParseMultiString(key_value.second, &locale_keywords_map_[""]);
      } else if (key == kDesktopEntryCategories) {
        ParseMultiString(key_value.second, &categories_);
      } else if (key == kDesktopEntryStartupWmClass) {
        startup_wm_class_ = UnescapeString(key_value.second);
      } else if (key == kDesktopEntryStartupNotify) {
        startup_notify_ = ParseBool(key_value.second);
      } else if (key == kDesktopEntrySteamAppId) {
        if (!base::StringToUint64(key_value.second, &steam_app_id_)) {
          LOG(WARNING) << "Failed to parse " << kDesktopEntrySteamAppId;
        }
      } else if (base::StartsWith(key, kDesktopEntryNameWithLocale,
                                  base::CompareCase::SENSITIVE)) {
        std::string locale = ExtractKeyLocale(key);
        if (locale.empty()) {
          continue;
        }
        locale_name_map_[locale] = UnescapeString(key_value.second);
      } else if (base::StartsWith(key, kDesktopEntryCommentWithLocale,
                                  base::CompareCase::SENSITIVE)) {
        std::string locale = ExtractKeyLocale(key);
        if (locale.empty()) {
          continue;
        }
        locale_comment_map_[locale] = UnescapeString(key_value.second);
      } else if (base::StartsWith(key, kDesktopEntryKeywordsWithLocale,
                                  base::CompareCase::SENSITIVE)) {
        std::string locale = ExtractKeyLocale(key);
        if (locale.empty()) {
          continue;
        }
        ParseMultiString(key_value.second, &locale_keywords_map_[locale]);
      }
    }
  }

  // Validate that the desktop file has the required entries in it.
  // First check the Type key.
  bool valid_type_found = false;
  for (const char* valid_type : kValidDesktopEntryTypes) {
    if (entry_type_ == valid_type) {
      valid_type_found = true;
      break;
    }
  }
  if (!valid_type_found) {
    LOG(ERROR) << "Failed parsing desktop file " << file_path.value()
               << " due to invalid Type key of: " << entry_type_;
    return false;
  }
  // Now check for a valid name.
  if (locale_name_map_.find("") == locale_name_map_.end()) {
    LOG(ERROR) << "Failed parsing desktop file " << file_path.value()
               << " due to missing unlocalized Name entry";
    return false;
  }
  // Since it's valid, set the ID based on the path name. This is done by
  // taking all the path values after "applications" in the path, appending them
  // with dash separators and then removing the .desktop extension from the
  // actual filename.
  // First verify this was actually a .desktop file.
  if (file_path.FinalExtension() != kDesktopFileExtension) {
    LOG(ERROR) << "Failed parsing desktop file due to invalid file extension: "
               << file_path.value();
    return false;
  }
  std::vector<std::string> path_comps =
      file_path.RemoveFinalExtension().GetComponents();
  bool found_path_delim = false;
  for (const auto& comp : path_comps) {
    if (!found_path_delim) {
      found_path_delim = (comp == kDesktopPathStartDelimiter);
      continue;
    }
    if (!app_id_.empty()) {
      app_id_.push_back('-');
    }
    app_id_.append(comp);
  }

  return true;
}

std::vector<std::string> DesktopFile::GenerateArgvWithFiles(
    const std::vector<std::string>& app_args) const {
  std::vector<std::string> retval;
  if (exec_.empty()) {
    return retval;
  }
  // We have already unescaped this string, which we are supposed to do first
  // according to the spec. We need to process this to handle quoted arguments
  // and also field code substitution.
  std::string curr_arg;
  bool in_quotes = false;
  bool next_escaped = false;
  bool next_field_code = false;
  for (auto c : exec_) {
    if (next_escaped) {
      next_escaped = false;
      curr_arg.push_back(c);
      continue;
    }
    if (c == '"') {
      if (in_quotes && !curr_arg.empty()) {
        // End of a quoted argument.
        retval.emplace_back(std::move(curr_arg));
        curr_arg.clear();
      }
      in_quotes = !in_quotes;
      continue;
    }
    if (in_quotes) {
      // There is no field expansion inside quotes, so just append the char
      // unless we have escaping. We only deal with escaping inside of quoted
      // strings here.
      if (c == '\\') {
        next_escaped = true;
        continue;
      }
      curr_arg.push_back(c);
      continue;
    }
    if (next_field_code) {
      next_field_code = false;
      if (c == '%') {
        // Escaped percent sign (I don't know why they just didn't use backslash
        // for escaping percent).
        curr_arg.push_back(c);
        continue;
      }
      switch (c) {
        case 'u':  // Single URL field code.
        case 'f':  // Single file field code.
          if (!app_args.empty()) {
            curr_arg.append(app_args.front());
          }
          continue;
        case 'U':  // Multiple URLs field code.
        case 'F':  // Multiple files field code.
          // For multi-args, the spec is explicit that each file is passed as
          // a separate arg to the program and that %U and %F must only be
          // used as an argument on their own, so complete any active arg
          // that we may have been parsing.
          if (!curr_arg.empty()) {
            retval.emplace_back(std::move(curr_arg));
            curr_arg.clear();
          }
          if (!app_args.empty()) {
            retval.insert(retval.end(), app_args.begin(), app_args.end());
          }
          continue;
        case 'i':  // Icon field code, expands to 2 args.
          if (!curr_arg.empty()) {
            retval.emplace_back(std::move(curr_arg));
            curr_arg.clear();
          }
          if (!icon_.empty()) {
            retval.emplace_back("--icon");
            retval.emplace_back(icon_);
          }
          continue;
        case 'c':  // Translated app name.
          // TODO(jkardatzke): Determine the proper localized name for the app.
          // We enforce that this key exists when we populate the object.
          curr_arg.append(locale_name_map_.find("")->second);
          continue;
        case 'k':  // Path to the desktop file itself.
          curr_arg.append(file_path_.value());
          continue;
        default:  // Unrecognized/deprecated field code. Unrecognized ones are
                  // technically invalid, but it seems better to just ignore
                  // them then completely abort executing this desktop file.
          continue;
      }
    }
    if (c == ' ') {
      // Argument separator.
      if (!curr_arg.empty()) {
        retval.emplace_back(std::move(curr_arg));
        curr_arg.clear();
      }
      continue;
    }
    if (c == '%') {
      next_field_code = true;
      continue;
    }
    curr_arg.push_back(c);
  }
  if (!curr_arg.empty()) {
    retval.emplace_back(std::move(curr_arg));
  }
  return retval;
}

std::string DesktopFile::GenerateExecutableFileName() const {
  std::vector<std::string> ArgvWithFiles = GenerateArgvWithFiles({});
  if (ArgvWithFiles.empty())
    return "";
  return base::FilePath(ArgvWithFiles.at(0)).BaseName().MaybeAsASCII();
}

bool DesktopFile::ShouldPassToHost() const {
  // Rules to follow:
  // -Only allow Applications.
  // -Don't pass hidden.
  // -Don't pass without an exec entry.
  // -Don't pass no_display that also have no mime types.
  // -Don't pass if in the Settings category.
  // -Don't pass if OnlyShowIn exists and doesn't contain kDesktopType.
  // -Don't pass if NotShowIn exists and contains kDesktopType.
  // -Don't pass if TryExec doesn't resolve to a valid executable file.
  if (!IsApplication() || hidden_ || exec_.empty() ||
      (no_display_ && mime_types_.empty())) {
    return false;
  }

  if (std::find(categories_.begin(), categories_.end(), kSettingsCategory) !=
      categories_.end()) {
    return false;
  }

  if (!only_show_in_.empty() &&
      std::find(only_show_in_.begin(), only_show_in_.end(), kDesktopType) ==
          only_show_in_.end()) {
    return false;
  }

  if (!not_show_in_.empty() &&
      std::find(not_show_in_.begin(), not_show_in_.end(), kDesktopType) !=
          not_show_in_.end()) {
    return false;
  }

  if (!try_exec_.empty()) {
    // If it's absolute, we just check it the way it is.
    base::FilePath try_exec_path(try_exec_);
    if (try_exec_path.IsAbsolute()) {
      int permissions;
      if (!base::GetPosixFilePermissions(try_exec_path, &permissions) ||
          !(permissions & base::FILE_PERMISSION_EXECUTE_BY_USER)) {
        return false;
      }
    } else {
      // Search the system path instead.
      std::string path;
      if (!base::Environment::Create()->GetVar(kPathEnvVar, &path)) {
        // If there's no PATH set we can't search.
        return false;
      }
      bool found_match = false;
      for (const base::StringPiece& cur_path : base::SplitStringPiece(
               path, ":", base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY)) {
        base::FilePath file(cur_path);
        int permissions;
        if (base::GetPosixFilePermissions(file.Append(try_exec_),
                                          &permissions) &&
            (permissions & base::FILE_PERMISSION_EXECUTE_BY_USER)) {
          found_match = true;
          break;
        }
      }
      if (!found_match) {
        return false;
      }
    }
  }

  return true;
}

bool DesktopFile::IsApplication() const {
  return entry_type_ == kDesktopEntryTypeApplication;
}

}  // namespace garcon
}  // namespace vm_tools
