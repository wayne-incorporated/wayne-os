// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_SETUP_XML_ANDROID_XML_UTIL_H_
#define ARC_SETUP_XML_ANDROID_XML_UTIL_H_

#include <string>

#include <base/component_export.h>
#include <base/files/file_path.h>
#include <base/functional/callback.h>

namespace arc {

// Reads Android's packages.xml at |packages_xml_path|, fills
// |out_fingerprint| and |out_sdk_version| with the OS fingerprint and the SDK
// version for the internal storage found in the XML.
// If the file does not exist or no fingerprint is found in the file, returns
// false.
COMPONENT_EXPORT(LIBANDROIDXML)
bool GetFingerprintAndSdkVersionFromPackagesXml(
    const base::FilePath& packages_xml_path,
    std::string* out_fingerprint,
    std::string* out_sdk_version);

// Reads Android's binary-format packages.xml at |packages_xml_path|, fills
// |out_fingerprint| and |out_sdk_version| with the OS fingerprint and the SDK
// version for the internal storage found in the XML.
// If the file does not exist or no fingerprint is found in the file, returns
// false.
COMPONENT_EXPORT(LIBANDROIDXML)
bool GetFingerprintAndSdkVersionFromBinaryPackagesXml(
    const base::FilePath& packages_xml_path,
    std::string* out_fingerprint,
    std::string* out_sdk_version);

// Reads |file_path| line by line and pass each line to the |callback| after
// trimming it. If |callback| returns true, stops reading the file and returns
// true.
COMPONENT_EXPORT(LIBANDROIDXML)
bool FindLine(
    const base::FilePath& file_path,
    const base::RepeatingCallback<bool(const std::string&)>& callback);

// A callback function for GetFingerprintAndSdkVersionFromPackagesXml.
// This checks if the |line| is like
//    <version sdkVersion="25" databaseVersion="3" fingerprint="..." />
// and store the fingerprint part in |out_fingerprint| and the sdkVersion part
// in |out_sdk_version| if it is. Ignore a line with a volumeUuid attribute
// which means that the line is for an external storage.
// What we need is a fingerprint and a sdk version for an internal storage.
COMPONENT_EXPORT(LIBANDROIDXML)
bool FindFingerprintAndSdkVersion(std::string* out_fingerprint,
                                  std::string* out_sdk_version,
                                  const std::string& line);

// Extracts media provider user id. It analyzes two files, packages.xml and
// packages_cache.xml and extracts package information associated with media
// provider. Note, packages.xml might not be available during the initial boot
// so packages_cache.xml is used as a fallback. For manual pushed images
// packages_cache.xml may not exist as well. |packages_xml_path| specifies the
// path to find packages_cache.xml. If media provider is found it returns true
// and |out_uid| is set.
COMPONENT_EXPORT(LIBANDROIDXML)
bool FindMediaProviderUid(const base::FilePath& packages_xml_path,
                          int* out_uid);

}  // namespace arc

#endif  // ARC_SETUP_XML_ANDROID_XML_UTIL_H_
