// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sysexits.h>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <optional>

#include <brillo/flag_helper.h>
#include <brillo/http/http_request.h>
#include <brillo/http/http_transport.h>
#include <chromeos/libipp/attribute.h>
#include <chromeos/libipp/builder.h>
#include <chromeos/libipp/frame.h>
#include <chromeos/libipp/parser.h>

#include "helpers.h"
#include "ipp_in_json.h"

namespace {

// Help message about the application.
constexpr char app_info[] =
    "This tool tries to send IPP "
    "Get-Printer-Attributes request to given URL and parse obtained "
    "response. If no output files are specified, the obtained response "
    "is printed to stdout as formatted JSON";

// Prints information about HTTP error to stderr.
void PrintHttpError(const std::string& msg, const brillo::ErrorPtr* err_ptr) {
  std::cerr << "Error occured at HTTP level: " << msg << "\n";
  if (err_ptr != nullptr && err_ptr->get() != nullptr) {
    std::cerr << "Reported errors stack:\n";
    for (const brillo::Error* error = err_ptr->get(); error != nullptr;
         error = error->GetInnerError()) {
      std::cerr << error->GetDomain() << ":";
      std::cerr << error->GetCode() << ":";
      std::cerr << error->GetLocation().file_name() << ",";
      std::cerr << error->GetLocation().function_name() << ",";
      std::cerr << error->GetLocation().line_number() << ":";
      std::cerr << error->GetMessage() << "\n";
    }
  }
  std::cerr << std::flush;
}

// Sends IPP frame (in |data| parameter) to given URL. In case of error, it
// prints out error message to stderr and returns nullopt. Otherwise, it returns
// the body from the response.
std::optional<std::vector<uint8_t>> SendIppFrameAndGetResponse(
    std::string url, const std::vector<uint8_t>& data) {
  using Transport = brillo::http::Transport;
  using Request = brillo::http::Request;
  using Response = brillo::http::Response;
  // Prepare HTTP request.
  std::shared_ptr<Transport> transport = Transport::CreateDefault();
  transport->UseCustomCertificate(Transport::Certificate::kNss);
  Request request(url, "POST", transport);
  request.SetContentType("application/ipp");
  brillo::ErrorPtr error;
  if (!data.empty()) {
    if (!request.AddRequestBody(data.data(), data.size(), &error)) {
      PrintHttpError("cannot set request body", &error);
      return std::nullopt;
    }
  }
  // Send the request and interpret obtained response.
  std::unique_ptr<Response> response = request.GetResponseAndBlock(&error);
  if (response == nullptr) {
    PrintHttpError("exchange failed", &error);
    return std::nullopt;
  }
  if (!response->IsSuccessful()) {
    const std::string msg = "unexpected response code: " +
                            std::to_string(response->GetStatusCode());
    PrintHttpError(msg, &error);
    return std::nullopt;
  }
  return (response->ExtractData());
}

// Write the content of given buffer to given filename ("location"). When
// "location" equals "-", the content is written to stdout. In case of an error,
// it prints out error message to stderr and returns false. The "buffer"
// parameter cannot be nullptr, exactly "size" elements is read from it.
bool WriteBufferToLocation(const char* buffer,
                           unsigned size,
                           const std::string& location) {
  if (location == "-") {
    std::cout.write(buffer, size);
    std::cout << std::endl;
    if (std::cout.bad()) {
      std::cerr << "Error when writing results to standard output.\n";
      return false;
    }
  } else {
    std::ofstream file(location, std::ios::binary | std::ios::trunc);
    if (!file.good()) {
      std::cerr << "Error when opening the file " << location << ".\n";
      return false;
    }
    file.write(buffer, size);
    file.close();
    if (file.bad()) {
      std::cerr << "Error when writing to the file " << location << ".\n";
      return false;
    }
  }
  return true;
}

}  // namespace

// Return codes:
// * EX_USAGE or EX_DATAERR: incorrect command line parameters
// * -1: cannot build IPP request (libipp error)
// * -2: HTTP exchange error (brillo/http or HTTP error)
// * -3: cannot save an output to given file (I/O error?)
// * -4: cannot build JSON output (base/json error).
// * -5: cannot parse IPP response (incorrect frame was received)
int main(int argc, char** argv) {
  // Define and parse command line parameters, exit if incorrect.
  DEFINE_string(
      url, "", "Address to query, supported protocols: http, https, ipp, ipps");
  DEFINE_string(version, "1.1", "IPP version (default 1.1)");
  DEFINE_string(
      jsonf, "",
      "Save the response as formatted JSON to given file (use - for stdout)");
  DEFINE_string(
      jsonc, "",
      "Save the response as compressed JSON to given file (use - for stdout)");
  DEFINE_string(
      binary, "",
      "Dump the response to given file as a binary content (use - for stdout)");
  brillo::FlagHelper::Init(argc, argv, app_info);
  auto free_params = base::CommandLine::ForCurrentProcess()->GetArgs();
  if (!free_params.empty()) {
    std::cerr << "Unknown parameters:";
    for (auto param : free_params) {
      std::cerr << " " << param;
    }
    std::cerr << std::endl;
    return EX_USAGE;
  }
  // Replace ipp/ipps protocol in the given URL to http/https (if needed).
  if (!ConvertIppToHttp(FLAGS_url)) {
    return EX_USAGE;
  }
  std::cerr << "URL: " << FLAGS_url << std::endl;
  // Parse the IPP version.
  ipp::Version version;
  if (!ipp::FromString(FLAGS_version, &version)) {
    std::cerr << "Unknown version: " << FLAGS_version << ". ";
    std::cerr << "Allowed values: 1.0, 1.1, 2.0, 2.1, 2.2." << std::endl;
    return EX_USAGE;
  }
  std::cerr << "IPP version: " << ipp::ToString(version) << std::endl;
  // If no output files were specified, set the default settings.
  if (FLAGS_binary.empty() && FLAGS_jsonc.empty() && FLAGS_jsonf.empty())
    FLAGS_jsonf = "-";

  // Send IPP request and get a response.
  ipp::Frame request(ipp::Operation::Get_Printer_Attributes, version);
  ipp::Collection& grp = request.Groups(ipp::GroupTag::operation_attributes)[0];
  grp.AddAttr("printer-uri", ipp::ValueTag::uri, FLAGS_url);
  std::vector<uint8_t> data = ipp::BuildBinaryFrame(request);
  auto data_optional = SendIppFrameAndGetResponse(FLAGS_url, data);
  if (!data_optional)
    return -2;
  data = std::move(*data_optional);
  // Write raw frame to file if needed.
  if (!FLAGS_binary.empty()) {
    if (!WriteBufferToLocation(reinterpret_cast<const char*>(data.data()),
                               data.size(), FLAGS_binary)) {
      return -3;
    }
  }

  // Parse the IPP response and save results.
  int return_code = 0;
  ipp::SimpleParserLog log;
  ipp::Frame response = ipp::Parse(data.data(), data.size(), log);
  if (!log.CriticalErrors().empty()) {
    std::cerr << "Parsing of an obtained response was not completed."
              << std::endl;
    return_code = -5;
    // Let's continue, we can still return some data (it is not our error).
  }
  if (!FLAGS_jsonc.empty()) {
    std::string json;
    if (!ConvertToJson(response, log, true, &json)) {
      std::cerr << "Error when preparing a report in JSON (compressed)."
                << std::endl;
      return -4;
    }
    if (!WriteBufferToLocation(json.data(), json.size(), FLAGS_jsonc)) {
      return -3;
    }
  }
  if (!FLAGS_jsonf.empty()) {
    std::string json;
    if (!ConvertToJson(response, log, false, &json)) {
      std::cerr << "Error when preparing a report in JSON (formatted)."
                << std::endl;
      return -4;
    }
    if (!WriteBufferToLocation(json.data(), json.size(), FLAGS_jsonf)) {
      return -3;
    }
  }

  return return_code;
}
