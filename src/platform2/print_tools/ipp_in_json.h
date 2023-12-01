// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PRINT_TOOLS_IPP_IN_JSON_H_
#define PRINT_TOOLS_IPP_IN_JSON_H_

#include <string>
#include <vector>

#include <chromeos/libipp/frame.h>
#include <chromeos/libipp/parser.h>

// This function build JSON representation of the given IPP response along with
// the log from parsing it. When `compressed_json` is true, produced JSON
// content contains no unnecessary whitespaces what makes it as short as
// possible. When `compressed_json` is false, produced JSON is formatted to
// maximize readability.
bool ConvertToJson(const ipp::Frame& response,
                   const ipp::SimpleParserLog& log,
                   bool compressed_json,
                   std::string* json);

#endif  //  PRINT_TOOLS_IPP_IN_JSON_H_
