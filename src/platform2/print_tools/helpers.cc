// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "helpers.h"

#include <iostream>
#include <string>

bool ConvertIppToHttp(std::string& url) {
  auto pos = url.find("://");
  if (pos == std::string::npos) {
    std::cerr << "Incorrect URL: " << url << ".\n";
    std::cerr << "You have to set url parameter, e.g.:";
    std::cerr << " --url=ipp://10.11.12.13/ipp/print." << std::endl;
    return false;
  }
  const auto protocol = url.substr(0, pos);
  if (protocol == "http" || protocol == "https") {
    return true;
  }
  std::string default_port;
  if (protocol == "ipp") {
    default_port = "631";
  } else if (protocol == "ipps") {
    default_port = "443";
  } else {
    std::cerr << "Incorrect URL protocol: " << protocol << ".\n";
    std::cerr << "Supported protocols: http, https, ipp, ipps." << std::endl;
    return false;
  }
  url = "htt" + url.substr(2);
  pos += 4;
  pos = url.find_first_of(":/?#", pos);
  if (pos == std::string::npos) {
    url += ":" + default_port;
  } else if (url[pos] != ':') {
    url = url.substr(0, pos) + ":" + default_port + url.substr(pos);
  }
  return true;
}
