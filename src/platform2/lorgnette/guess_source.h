// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LORGNETTE_GUESS_SOURCE_H_
#define LORGNETTE_GUESS_SOURCE_H_

#include <string>

#include <lorgnette/proto_bindings/lorgnette_service.pb.h>

// Given a string representing a scanning source (for example, 'Platen',
// 'Flatbed', 'ADF', etc.), attempts to guess what scanner source type that
// name represents. If no match is found, returns SOURCE_UNSPECIFIED.
// Comparisons are case-insensitive.
lorgnette::SourceType GuessSourceType(const std::string& name);

#endif  // LORGNETTE_GUESS_SOURCE_H_
