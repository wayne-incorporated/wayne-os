// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package introspect

import (
	"encoding/xml"
)

// Parse converts introspection from the XML to a structure.
func Parse(content []byte) (Introspection, error) {
	var i Introspection
	if err := xml.Unmarshal(content, &i); err != nil {
		return Introspection{}, err
	}
	if err := verifyIntrospection(&i); err != nil {
		return Introspection{}, err
	}
	return i, nil
}
