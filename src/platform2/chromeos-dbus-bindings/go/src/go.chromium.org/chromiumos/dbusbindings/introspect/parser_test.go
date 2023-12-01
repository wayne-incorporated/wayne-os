// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package introspect_test

import (
	"testing"

	"go.chromium.org/chromiumos/dbusbindings/introspect"

	"github.com/google/go-cmp/cmp"
)

const (
	nonXMLContents = "This has no resemblance to XML"
	eof            = "EOF"

	ungrammaticalXMLContents = "<node>"
	unexpectedEOF            = "XML syntax error on line 1: unexpected EOF"

	goodXMLContents = `
<node name="/org/chromium/Test"
      xmlns:tp="http://telepathy.freedesktop.org/wiki/DbusSpec#extensions-v0">
  <interface name="fi.w1.wpa_supplicant1.Interface">
    <method name="Scan">
      <arg name="args" type="a{sv}"/>
    </method>
    <method name="PassMeProtos">
      <arg name="request" type="ay" direction="in">
        <annotation name="org.chromium.DBus.Argument.ProtobufClass" value="PassMeProtosRequest" />
      </arg>
      <annotation name="org.chromium.DBus.Method.Kind" value="async"/>
      <tp:docstring>
        doc1
      </tp:docstring>
    </method>
    <signal name="BSSRemoved">
      <arg name="BSSDetail" type="ay">
        <annotation name="org.chromium.DBus.Argument.ProtobufClass" value="YetAnotherProto" />
      </arg>
      <tp:docstring>
        doc2
      </tp:docstring>
    </signal>
    <property name="Capabilities" type="a{sv}" access="read">
      <tp:docstring>
        doc3
      </tp:docstring>
    </property>
    <tp:docstring>
      doc4
    </tp:docstring>
  </interface>
  <interface name="DummyInterface" />
</node>
	`
)

func TestNonXMLContents(t *testing.T) {
	if _, err := introspect.Parse([]byte(nonXMLContents)); err.Error() != eof {
		t.Errorf("Parse err mismatch: got %q, want %q", err, eof)
	}
}

func TestUngrammaticalXMLContents(t *testing.T) {
	if _, err := introspect.Parse([]byte(ungrammaticalXMLContents)); err.Error() != unexpectedEOF {
		t.Errorf("Parse err mismatch: got %q, want %q", err, unexpectedEOF)
	}
}

func TestGoodXMLContents(t *testing.T) {
	got, err := introspect.Parse([]byte(goodXMLContents))
	if err != nil {
		t.Errorf("Parse got error, want nil: %v", err)
	}

	itf := introspect.Interface{
		Name: "fi.w1.wpa_supplicant1.Interface",
		Methods: []introspect.Method{
			{
				Name: "Scan",
				Args: []introspect.MethodArg{
					{
						Name:       "args",
						Type:       "a{sv}",
						Direction:  "",
						Annotation: introspect.Annotation{"", ""},
					},
				},
				Annotations: nil,
				DocString:   "",
			}, {
				Name: "PassMeProtos",
				Args: []introspect.MethodArg{
					{
						Name:      "request",
						Type:      "ay",
						Direction: "in",
						Annotation: introspect.Annotation{
							Name:  "org.chromium.DBus.Argument.ProtobufClass",
							Value: "PassMeProtosRequest",
						},
					},
				},
				Annotations: []introspect.Annotation{
					{
						Name:  "org.chromium.DBus.Method.Kind",
						Value: "async",
					},
				},
				DocString: "\n        doc1\n      ",
			},
		},
		Signals: []introspect.Signal{
			{
				Name: "BSSRemoved",
				Args: []introspect.SignalArg{
					{
						Name: "BSSDetail",
						Type: "ay",
						Annotation: introspect.Annotation{
							Name:  "org.chromium.DBus.Argument.ProtobufClass",
							Value: "YetAnotherProto",
						},
					},
				},
				DocString: "\n        doc2\n      ",
			},
		},
		Properties: []introspect.Property{
			{
				Name:      "Capabilities",
				Type:      "a{sv}",
				Access:    "read",
				DocString: "\n        doc3\n      ",
			},
		},
		DocString: "\n      doc4\n    ",
	}

	want := introspect.Introspection{
		Name: "/org/chromium/Test",
		Interfaces: []introspect.Interface{
			itf,
			{"DummyInterface", nil, nil, nil, ""},
		},
	}

	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("Parse failed (-got +want):\n%s", diff)
	}
}
