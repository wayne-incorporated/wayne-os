// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/check.h>
#include <brillo/http/http_utils.h>

#include <algorithm>
#include <optional>

#include <base/functional/bind.h>
#include <base/json/json_reader.h>
#include <base/json/json_writer.h>
#include <base/values.h>
#include <brillo/data_encoding.h>
#include <brillo/errors/error_codes.h>
#include <brillo/mime_utils.h>
#include <brillo/streams/memory_stream.h>

using brillo::mime::AppendParameter;
using brillo::mime::RemoveParameters;

namespace brillo {
namespace http {

std::unique_ptr<Response> GetAndBlock(const std::string& url,
                                      const HeaderList& headers,
                                      std::shared_ptr<Transport> transport,
                                      brillo::ErrorPtr* error) {
  return SendRequestWithNoDataAndBlock(request_type::kGet, url, headers,
                                       transport, error);
}

RequestID Get(const std::string& url,
              const HeaderList& headers,
              std::shared_ptr<Transport> transport,
              SuccessCallback success_callback,
              ErrorCallback error_callback) {
  return SendRequestWithNoData(request_type::kGet, url, headers, transport,
                               std::move(success_callback),
                               std::move(error_callback));
}

std::unique_ptr<Response> HeadAndBlock(const std::string& url,
                                       std::shared_ptr<Transport> transport,
                                       brillo::ErrorPtr* error) {
  return SendRequestWithNoDataAndBlock(request_type::kHead, url, {}, transport,
                                       error);
}

RequestID Head(const std::string& url,
               std::shared_ptr<Transport> transport,
               SuccessCallback success_callback,
               ErrorCallback error_callback) {
  return SendRequestWithNoData(request_type::kHead, url, {}, transport,
                               std::move(success_callback),
                               std::move(error_callback));
}

std::unique_ptr<Response> PostTextAndBlock(const std::string& url,
                                           const std::string& data,
                                           const std::string& mime_type,
                                           const HeaderList& headers,
                                           std::shared_ptr<Transport> transport,
                                           brillo::ErrorPtr* error) {
  return PostBinaryAndBlock(url, data.data(), data.size(), mime_type, headers,
                            transport, error);
}

RequestID PostText(const std::string& url,
                   const std::string& data,
                   const std::string& mime_type,
                   const HeaderList& headers,
                   std::shared_ptr<Transport> transport,
                   SuccessCallback success_callback,
                   ErrorCallback error_callback) {
  return PostBinary(url, data.data(), data.size(), mime_type, headers,
                    transport, std::move(success_callback),
                    std::move(error_callback));
}

std::unique_ptr<Response> SendRequestAndBlock(
    const std::string& method,
    const std::string& url,
    const void* data,
    size_t data_size,
    const std::string& mime_type,
    const HeaderList& headers,
    std::shared_ptr<Transport> transport,
    brillo::ErrorPtr* error) {
  Request request(url, method, transport);
  request.AddHeaders(headers);
  if (data_size > 0) {
    CHECK(!mime_type.empty()) << "MIME type must be specified if request body "
                                 "message is provided";
    request.SetContentType(mime_type);
    if (!request.AddRequestBody(data, data_size, error))
      return std::unique_ptr<Response>();
  }
  return request.GetResponseAndBlock(error);
}

std::unique_ptr<Response> SendRequestWithNoDataAndBlock(
    const std::string& method,
    const std::string& url,
    const HeaderList& headers,
    std::shared_ptr<Transport> transport,
    brillo::ErrorPtr* error) {
  return SendRequestAndBlock(method, url, nullptr, 0, {}, headers, transport,
                             error);
}

RequestID SendRequest(const std::string& method,
                      const std::string& url,
                      StreamPtr stream,
                      const std::string& mime_type,
                      const HeaderList& headers,
                      std::shared_ptr<Transport> transport,
                      SuccessCallback success_callback,
                      ErrorCallback error_callback) {
  Request request(url, method, transport);
  request.AddHeaders(headers);
  if (stream && (!stream->CanGetSize() || stream->GetRemainingSize() > 0)) {
    CHECK(!mime_type.empty()) << "MIME type must be specified if request body "
                                 "message is provided";
    request.SetContentType(mime_type);
    brillo::ErrorPtr error;
    if (!request.AddRequestBody(std::move(stream), &error)) {
      transport->RunCallbackAsync(FROM_HERE,
                                  base::BindOnce(std::move(error_callback), 0,
                                                 base::Owned(error.release())));
      return 0;
    }
  }
  return request.GetResponse(std::move(success_callback),
                             std::move(error_callback));
}

RequestID SendRequest(const std::string& method,
                      const std::string& url,
                      const void* data,
                      size_t data_size,
                      const std::string& mime_type,
                      const HeaderList& headers,
                      std::shared_ptr<Transport> transport,
                      SuccessCallback success_callback,
                      ErrorCallback error_callback) {
  return SendRequest(method, url,
                     MemoryStream::OpenCopyOf(data, data_size, nullptr),
                     mime_type, headers, transport, std::move(success_callback),
                     std::move(error_callback));
}

RequestID SendRequestWithNoData(const std::string& method,
                                const std::string& url,
                                const HeaderList& headers,
                                std::shared_ptr<Transport> transport,
                                SuccessCallback success_callback,
                                ErrorCallback error_callback) {
  return SendRequest(method, url, {}, {}, headers, transport,
                     std::move(success_callback), std::move(error_callback));
}

std::unique_ptr<Response> PostBinaryAndBlock(
    const std::string& url,
    const void* data,
    size_t data_size,
    const std::string& mime_type,
    const HeaderList& headers,
    std::shared_ptr<Transport> transport,
    brillo::ErrorPtr* error) {
  return SendRequestAndBlock(request_type::kPost, url, data, data_size,
                             mime_type, headers, transport, error);
}

RequestID PostBinary(const std::string& url,
                     StreamPtr stream,
                     const std::string& mime_type,
                     const HeaderList& headers,
                     std::shared_ptr<Transport> transport,
                     SuccessCallback success_callback,
                     ErrorCallback error_callback) {
  return SendRequest(request_type::kPost, url, std::move(stream), mime_type,
                     headers, transport, std::move(success_callback),
                     std::move(error_callback));
}

RequestID PostBinary(const std::string& url,
                     const void* data,
                     size_t data_size,
                     const std::string& mime_type,
                     const HeaderList& headers,
                     std::shared_ptr<Transport> transport,
                     SuccessCallback success_callback,
                     ErrorCallback error_callback) {
  return SendRequest(request_type::kPost, url, data, data_size, mime_type,
                     headers, transport, std::move(success_callback),
                     std::move(error_callback));
}

std::unique_ptr<Response> PostFormDataAndBlock(
    const std::string& url,
    const FormFieldList& data,
    const HeaderList& headers,
    std::shared_ptr<Transport> transport,
    brillo::ErrorPtr* error) {
  std::string encoded_data = brillo::data_encoding::WebParamsEncode(data);
  return PostBinaryAndBlock(url, encoded_data.c_str(), encoded_data.size(),
                            brillo::mime::application::kWwwFormUrlEncoded,
                            headers, transport, error);
}

std::unique_ptr<Response> PostFormDataAndBlock(
    const std::string& url,
    std::unique_ptr<FormData> form_data,
    const HeaderList& headers,
    std::shared_ptr<Transport> transport,
    brillo::ErrorPtr* error) {
  Request request(url, request_type::kPost, transport);
  request.AddHeaders(headers);
  if (!request.AddRequestBodyAsFormData(std::move(form_data), error))
    return std::unique_ptr<Response>();
  return request.GetResponseAndBlock(error);
}

RequestID PostFormData(const std::string& url,
                       const FormFieldList& data,
                       const HeaderList& headers,
                       std::shared_ptr<Transport> transport,
                       SuccessCallback success_callback,
                       ErrorCallback error_callback) {
  std::string encoded_data = brillo::data_encoding::WebParamsEncode(data);
  return PostBinary(url, encoded_data.c_str(), encoded_data.size(),
                    brillo::mime::application::kWwwFormUrlEncoded, headers,
                    transport, std::move(success_callback),
                    std::move(error_callback));
}

RequestID PostFormData(const std::string& url,
                       std::unique_ptr<FormData> form_data,
                       const HeaderList& headers,
                       std::shared_ptr<Transport> transport,
                       SuccessCallback success_callback,
                       ErrorCallback error_callback) {
  Request request(url, request_type::kPost, transport);
  request.AddHeaders(headers);
  brillo::ErrorPtr error;
  if (!request.AddRequestBodyAsFormData(std::move(form_data), &error)) {
    transport->RunCallbackAsync(FROM_HERE,
                                base::BindOnce(std::move(error_callback), 0,
                                               base::Owned(error.release())));
    return 0;
  }
  return request.GetResponse(std::move(success_callback),
                             std::move(error_callback));
}

std::unique_ptr<Response> PostJsonAndBlock(const std::string& url,
                                           const base::Value* json,
                                           const HeaderList& headers,
                                           std::shared_ptr<Transport> transport,
                                           brillo::ErrorPtr* error) {
  std::string data;
  if (json)
    base::JSONWriter::Write(*json, &data);
  std::string mime_type =
      AppendParameter(brillo::mime::application::kJson,
                      brillo::mime::parameters::kCharset, "utf-8");
  return PostBinaryAndBlock(url, data.c_str(), data.size(), mime_type, headers,
                            transport, error);
}

RequestID PostJson(const std::string& url,
                   std::unique_ptr<base::Value> json,
                   const HeaderList& headers,
                   std::shared_ptr<Transport> transport,
                   SuccessCallback success_callback,
                   ErrorCallback error_callback) {
  std::string data;
  if (json)
    base::JSONWriter::Write(*json, &data);
  std::string mime_type =
      AppendParameter(brillo::mime::application::kJson,
                      brillo::mime::parameters::kCharset, "utf-8");
  return PostBinary(url, data.c_str(), data.size(), mime_type, headers,
                    transport, std::move(success_callback),
                    std::move(error_callback));
}

std::unique_ptr<Response> PatchJsonAndBlock(
    const std::string& url,
    const base::Value* json,
    const HeaderList& headers,
    std::shared_ptr<Transport> transport,
    brillo::ErrorPtr* error) {
  std::string data;
  if (json)
    base::JSONWriter::Write(*json, &data);
  std::string mime_type =
      AppendParameter(brillo::mime::application::kJson,
                      brillo::mime::parameters::kCharset, "utf-8");
  return SendRequestAndBlock(request_type::kPatch, url, data.c_str(),
                             data.size(), mime_type, headers, transport, error);
}

RequestID PatchJson(const std::string& url,
                    std::unique_ptr<base::Value> json,
                    const HeaderList& headers,
                    std::shared_ptr<Transport> transport,
                    SuccessCallback success_callback,
                    ErrorCallback error_callback) {
  std::string data;
  if (json)
    base::JSONWriter::Write(*json, &data);
  std::string mime_type =
      AppendParameter(brillo::mime::application::kJson,
                      brillo::mime::parameters::kCharset, "utf-8");
  return SendRequest(request_type::kPatch, url, data.c_str(), data.size(),
                     mime_type, headers, transport, std::move(success_callback),
                     std::move(error_callback));
}

std::optional<base::Value::Dict> ParseJsonResponse(Response* response,
                                                   int* status_code,
                                                   brillo::ErrorPtr* error) {
  if (!response)
    return std::nullopt;

  if (status_code)
    *status_code = response->GetStatusCode();

  // Make sure we have a correct content type. Do not try to parse
  // binary files, or HTML output. Limit to application/json and text/plain.
  auto content_type = RemoveParameters(response->GetContentType());
  if (content_type != brillo::mime::application::kJson &&
      content_type != brillo::mime::text::kPlain) {
    brillo::Error::AddTo(error, FROM_HERE, brillo::errors::json::kDomain,
                         "non_json_content_type",
                         "Unexpected response content type: " + content_type);
    return std::nullopt;
  }

  std::string json = response->ExtractDataAsString();
  auto json_result =
      base::JSONReader::ReadAndReturnValueWithError(json, base::JSON_PARSE_RFC);
  if (!json_result.has_value()) {
    brillo::Error::AddToPrintf(error, FROM_HERE, brillo::errors::json::kDomain,
                               brillo::errors::json::kParseError,
                               "Error '%s' occurred parsing JSON string '%s'",
                               json_result.error().message.c_str(),
                               json.c_str());
    return std::nullopt;
  }
  if (!json_result->is_dict()) {
    brillo::Error::AddToPrintf(error, FROM_HERE, brillo::errors::json::kDomain,
                               brillo::errors::json::kObjectExpected,
                               "Response is not a valid dictionary: '%s'",
                               json.c_str());
    return std::nullopt;
  }
  return std::move(json_result->GetDict());
}

std::string GetCanonicalHeaderName(const std::string& name) {
  std::string canonical_name = name;
  bool word_begin = true;
  for (char& c : canonical_name) {
    if (c == '-') {
      word_begin = true;
    } else {
      if (word_begin) {
        c = toupper(c);
      } else {
        c = tolower(c);
      }
      word_begin = false;
    }
  }
  return canonical_name;
}

}  // namespace http
}  // namespace brillo
