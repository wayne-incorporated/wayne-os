// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <tuple>
#include <unordered_set>

#include <base/strings/strcat.h>
#include <base/uuid.h>

#include "missive/storage/storage_util.h"
#include "missive/util/file.h"
#include "missive/util/status.h"

namespace reporting {

// Find all subdirectories in the storage directory that represent storage
// queues based on the subdirectory name. Returns a set of tuples of
// <Priority,GenerationGuid> where each tuple represents a valid storage
// queue directory. Queue directories are named in the format:
// <Priority>.<GenerationGuid> (e.g. foo/bar/Security.Xhd34k,
// foo/bar/FastBatch.bKd3La1). If the directory name follows this format,
// then it is a valid queue directory so we parse the priority and
// generation guid and return them. The exception to this naming convention
// are legacy queue directories which may be named by priority with no
// generation guid (e.g. foo/bar/Security,  foo/bar/FastBatch). In this case
// we set the generation guid in the queue parameter to be an empty string.
StorageDirectory::Set StorageDirectory::FindQueueDirectories(
    const StorageOptions& options) {
  Set queue_params;
  base::FileEnumerator dir_enum(options.directory(),
                                /*recursive=*/false,
                                base::FileEnumerator::DIRECTORIES);
  for (auto full_name = dir_enum.Next(); !full_name.empty();
       full_name = dir_enum.Next()) {
    if (const auto priority_result =
            ParsePriorityFromQueueDirectory(full_name, options);
        priority_result.ok() && full_name.Extension().empty()) {
      // This is a legacy queue directory named just by priority with no
      // generation guid as an extension: foo/bar/Security,
      // foo/bar/FastBatch, etc.
      queue_params.emplace(
          std::make_tuple(priority_result.ValueOrDie(), GenerationGuid()));
      LOG(INFO) << "Found legacy queue directory: " << full_name;
    } else if (auto queue_param =
                   GetPriorityAndGenerationGuid(full_name, options);
               queue_param.ok()) {
      queue_params.emplace(queue_param.ValueOrDie());
    } else {
      LOG(INFO) << "Could not parse queue parameters from filename "
                << full_name.MaybeAsASCII()
                << " error = " << queue_param.status();
    }
  }
  return queue_params;
}

StatusOr<std::tuple<Priority, GenerationGuid>>
StorageDirectory::GetPriorityAndGenerationGuid(const base::FilePath& full_name,
                                               const StorageOptions& options) {
  // Try to parse generation guid from file path
  const auto generation_guid = ParseGenerationGuidFromFileName(full_name);
  if (!generation_guid.ok()) {
    return generation_guid.status();
  }
  // Try to parse a priority from file path
  const auto priority = ParsePriorityFromQueueDirectory(full_name, options);
  if (!priority.ok()) {
    return priority.status();
  }
  return std::make_tuple(priority.ValueOrDie(), generation_guid.ValueOrDie());
}

StatusOr<GenerationGuid> StorageDirectory::ParseGenerationGuidFromFileName(
    const base::FilePath& full_name) {
  // The string returned by `Extension()` includes the leading period, i.e
  // ".txt" instead of "txt", so remove the period just get the text part of
  // the extension.
  if (full_name.Extension().empty()) {
    return Status(
        error::DATA_LOSS,
        base::StrCat({"Could not parse generation GUID from queue directory ",
                      full_name.MaybeAsASCII()}));
  }

  std::string extension_without_leading_period =
      full_name.Extension().substr(1);

  const auto generation_guid =
      base::Uuid::ParseCaseInsensitive(extension_without_leading_period);
  if (!generation_guid.is_valid()) {
    return Status(
        error::DATA_LOSS,
        base::StrCat({"Could not parse generation GUID from queue directory ",
                      full_name.MaybeAsASCII()}));
  }
  return generation_guid.AsLowercaseString();
}

StatusOr<Priority> StorageDirectory::ParsePriorityFromQueueDirectory(
    const base::FilePath full_path, const StorageOptions& options) {
  for (const auto& priority_queue_options_pair :
       options.ProduceQueuesOptionsList()) {
    if (priority_queue_options_pair.second.directory() ==
        full_path.RemoveExtension()) {
      return priority_queue_options_pair.first;
    }
  }
  return Status(error::NOT_FOUND,
                base::StrCat({"Found no priority for queue directory ",
                              full_path.MaybeAsASCII()}));
}

bool StorageDirectory::DeleteEmptySubdirectories(
    const base::FilePath directory) {
  base::FileEnumerator dir_enum(directory,
                                /*recursive=*/false,
                                base::FileEnumerator::DIRECTORIES);
  return DeleteFilesWarnIfFailed(
      dir_enum, base::BindRepeating([](const base::FilePath& directory) {
        LOG(ERROR) << "Checking " << directory.MaybeAsASCII();
        if (base::IsDirectoryEmpty(directory)) {
          LOG(INFO) << "Deleting empty queue directory "
                    << directory.MaybeAsASCII();
          return true;
        }
        return false;
      }));
}
}  // namespace reporting
