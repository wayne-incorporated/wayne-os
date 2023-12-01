// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_GARCON_INI_PARSE_UTIL_H_
#define VM_TOOLS_GARCON_INI_PARSE_UTIL_H_

#include <string>
#include <utility>
#include <vector>

#include <base/strings/string_piece.h>

namespace vm_tools {
namespace garcon {

// Extracts name from "[Name]" formatted string, empty string returned if error.
base::StringPiece ParseGroupName(base::StringPiece group_line);

// Converts a boolean string value to primitive.
bool ParseBool(const std::string& s);

// Gets the locale value out of a key name, which is in the format:
// "key[locale]". Returns empty string if this had an invalid format.
std::string ExtractKeyLocale(const std::string& key);

// Returns a std::pair of strings that is extracted from the passed in string.
// This uses '=' as the delimiter between the key and value pair. Any whitespace
// around the '=' is removed. If there is no delimiter, then the second item in
// the pair will be empty.
std::pair<std::string, std::string> ExtractKeyValuePair(
    base::StringPiece entry_line);

// Converts all escaped chars in this string to their proper equivalent.
std::string UnescapeString(const std::string& s);

// Parses the passed in string into parts that are delimited by semicolon. This
// also allows escaping of semicolons with the backslash character which is why
// we can't use standard string splitting.
void ParseMultiString(const std::string& s,
                      std::vector<std::string>* out,
                      const char delimiter = ';');

}  // namespace garcon
}  // namespace vm_tools

#endif  // VM_TOOLS_GARCON_INI_PARSE_UTIL_H_
