// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_HTTP_MOCK_CURL_API_H_
#define LIBBRILLO_BRILLO_HTTP_MOCK_CURL_API_H_

#include <string>

#include <brillo/http/curl_api.h>
#include <gmock/gmock.h>

namespace brillo {
namespace http {

// This is a mock for CURL interfaces which allows to mock out the CURL's
// low-level C APIs in tests by intercepting the virtual function calls on
// the abstract CurlInterface.
class MockCurlInterface : public CurlInterface {
 public:
  MockCurlInterface() = default;
  MockCurlInterface(const MockCurlInterface&) = delete;
  MockCurlInterface& operator=(const MockCurlInterface&) = delete;

  MOCK_METHOD(CURL*, EasyInit, (), (override));
  MOCK_METHOD(void, EasyCleanup, (CURL*), (override));
  MOCK_METHOD(CURLcode, EasySetOptInt, (CURL*, CURLoption, int), (override));
  MOCK_METHOD(CURLcode,
              EasySetOptStr,
              (CURL*, CURLoption, const std::string&),
              (override));
  MOCK_METHOD(CURLcode, EasySetOptPtr, (CURL*, CURLoption, void*), (override));
  MOCK_METHOD(CURLcode,
              EasySetOptCallback,
              (CURL*, CURLoption, intptr_t),
              (override));
  MOCK_METHOD(CURLcode,
              EasySetOptOffT,
              (CURL*, CURLoption, curl_off_t),
              (override));
  MOCK_METHOD(CURLcode, EasyPerform, (CURL*), (override));
  MOCK_METHOD(CURLcode,
              EasyGetInfoInt,
              (CURL*, CURLINFO, int*),
              (const, override));
  MOCK_METHOD(CURLcode,
              EasyGetInfoDbl,
              (CURL*, CURLINFO, double*),
              (const, override));
  MOCK_METHOD(CURLcode,
              EasyGetInfoStr,
              (CURL*, CURLINFO, std::string*),
              (const, override));
  MOCK_METHOD(CURLcode,
              EasyGetInfoPtr,
              (CURL*, CURLINFO, void**),
              (const, override));
  MOCK_METHOD(std::string, EasyStrError, (CURLcode), (const, override));
  MOCK_METHOD(CURLM*, MultiInit, (), (override));
  MOCK_METHOD(CURLMcode, MultiCleanup, (CURLM*), (override));
  MOCK_METHOD(CURLMsg*, MultiInfoRead, (CURLM*, int*), (override));
  MOCK_METHOD(CURLMcode, MultiAddHandle, (CURLM*, CURL*), (override));
  MOCK_METHOD(CURLMcode, MultiRemoveHandle, (CURLM*, CURL*), (override));
  MOCK_METHOD(CURLMcode,
              MultiSetSocketCallback,
              (CURLM*, curl_socket_callback, void*),
              (override));
  MOCK_METHOD(CURLMcode,
              MultiSetTimerCallback,
              (CURLM*, curl_multi_timer_callback, void*),
              (override));
  MOCK_METHOD(CURLMcode,
              MultiAssign,
              (CURLM*, curl_socket_t, void*),
              (override));
  MOCK_METHOD(CURLMcode,
              MultiSocketAction,
              (CURLM*, curl_socket_t, int, int*),
              (override));
  MOCK_METHOD(std::string, MultiStrError, (CURLMcode), (const, override));
  MOCK_METHOD(CURLMcode, MultiPerform, (CURLM*, int*), (override));
  MOCK_METHOD(CURLMcode,
              MultiWait,
              (CURLM*, curl_waitfd[], unsigned int, int, int*),
              (override));
};

}  // namespace http
}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_HTTP_MOCK_CURL_API_H_
