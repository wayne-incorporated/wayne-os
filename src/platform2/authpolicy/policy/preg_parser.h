// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file provides a parser for PReg files which are used for storing group
// policy settings in the file system. The file format is documented here:
//
// http://msdn.microsoft.com/en-us/library/windows/desktop/aa374407(v=vs.85).aspx

#ifndef AUTHPOLICY_POLICY_PREG_PARSER_H_
#define AUTHPOLICY_POLICY_PREG_PARSER_H_

#include <memory>
#include <string>
#include <vector>

#include <components/policy/core/common/policy_load_status.h>

namespace base {
class FilePath;
}

namespace policy {

class RegistryDict;

namespace preg_parser {

// The magic header in PReg files: ASCII "PReg" + version (0x0001).
extern const char kPRegFileHeader[8];

// Reads the PReg file at |file_path| and writes the registry data to |dict|.
// |root| specifies the registry subtree the caller is interested in, everything
// else gets ignored. It may be empty if all keys should be returned, but it
// must NOT end with a backslash.
bool ReadFile(const base::FilePath& file_path,
              const std::u16string& root,
              RegistryDict* dict,
              PolicyLoadStatusSampler* status);

// Similar to ReadFile, but reads from |preg_data| of length |preg_data_size|
// instead of a file. |debug_name| is printed out along with error messages.
// Used internally and for testing only. All other callers should use ReadFile
// instead.
bool ReadDataInternal(const uint8_t* preg_data,
                      size_t preg_data_size,
                      const std::u16string& root,
                      RegistryDict* dict,
                      PolicyLoadStatusSampler* status,
                      const std::string& debug_name);

}  // namespace preg_parser
}  // namespace policy

#endif  // AUTHPOLICY_POLICY_PREG_PARSER_H_
