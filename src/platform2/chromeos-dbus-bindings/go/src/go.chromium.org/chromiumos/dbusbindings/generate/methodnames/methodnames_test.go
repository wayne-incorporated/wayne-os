// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package methodnames_test

import (
	"bytes"
	"testing"

	"go.chromium.org/chromiumos/dbusbindings/generate/methodnames"
	"go.chromium.org/chromiumos/dbusbindings/introspect"

	"github.com/google/go-cmp/cmp"
)

const (
	want = `
namespace fi {
namespace w1 {
namespace wpa_supplicant1 {
namespace Interface {
const char kScanMethod[] = "Scan";
const char kGetBlobMethod[] = "GetBlob";
}  // namespace Interface
}  // namespace wpa_supplicant1
}  // namespace w1
}  // namespace fi

namespace fi {
namespace w1 {
namespace wpa_supplicant1 {
namespace Interface2 {
const char kPassMeProtosMethod[] = "PassMeProtos";
}  // namespace Interface2
}  // namespace wpa_supplicant1
}  // namespace w1
}  // namespace fi

namespace fi {
namespace w1 {
namespace wpa_supplicant1 {
namespace Interface3 {
}  // namespace Interface3
}  // namespace wpa_supplicant1
}  // namespace w1
}  // namespace fi

namespace fi {
namespace w1 {
namespace wpa_supplicant2 {
namespace InterfaceA {
}  // namespace InterfaceA
}  // namespace wpa_supplicant2
}  // namespace w1
}  // namespace fi
`
)

func TestGenerateMethodnames(t *testing.T) {
	var introspections = []introspect.Introspection{
		{
			Interfaces: []introspect.Interface{
				{
					Name: "fi.w1.wpa_supplicant1.Interface",
					Methods: []introspect.Method{
						{
							Name: "Scan",
						}, {
							Name: "GetBlob",
						},
					},
				}, {
					Name: "fi.w1.wpa_supplicant1.Interface2",
					Methods: []introspect.Method{
						{
							Name: "PassMeProtos",
						},
					},
				}, {
					Name:    "fi.w1.wpa_supplicant1.Interface3",
					Methods: nil,
				},
			},
		}, {
			Interfaces: []introspect.Interface{
				{
					Name:    "fi.w1.wpa_supplicant2.InterfaceA",
					Methods: nil,
				},
			},
		},
	}

	out := new(bytes.Buffer)
	err := methodnames.Generate(introspections, out)
	if err != nil {
		t.Errorf("Generate got error, want nil: %v", err)
	}

	if diff := cmp.Diff(out.String(), want); diff != "" {
		t.Errorf(" failed (-got +want):\n%s", diff)
	}
}
