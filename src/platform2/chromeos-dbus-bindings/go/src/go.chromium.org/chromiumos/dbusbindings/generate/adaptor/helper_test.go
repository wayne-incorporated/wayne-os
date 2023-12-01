// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package adaptor

import (
	"testing"

	"go.chromium.org/chromiumos/dbusbindings/introspect"

	"github.com/google/go-cmp/cmp"
)

func TestMakeMethodRetType(t *testing.T) {
	cases := []struct {
		input introspect.Method
		want  string
	}{
		{
			input: introspect.Method{
				Name: "simpleMethodWithOnlyOutputArg1",
				Args: []introspect.MethodArg{
					{Name: "onlyOutput", Direction: "out", Type: "h"},
				},
				Annotations: []introspect.Annotation{
					{Name: "org.chromium.DBus.Method.Kind", Value: "simple"},
				},
			},
			want: "base::ScopedFD",
		}, {
			input: introspect.Method{
				Name: "simpleMethodWithOnlyOutputArg2",
				Args: []introspect.MethodArg{
					{Name: "onlyOutput",
						Direction: "out",
						Type:      "ay",
						Annotation: introspect.Annotation{
							Name:  "org.chromium.DBus.Argument.ProtobufClass",
							Value: "MyProtobufClass",
						},
					},
				},
				Annotations: []introspect.Annotation{
					{Name: "org.chromium.DBus.Method.Kind", Value: "simple"},
				},
			},
			want: "MyProtobufClass",
		}, {
			input: introspect.Method{
				Name: "normalMethod",
			},
			want: "bool",
		}, {
			input: introspect.Method{
				Name: "theOtherMethods",
				Annotations: []introspect.Annotation{
					{Name: "org.chromium.DBus.Method.Kind", Value: "simple"},
				},
			},
			want: "void",
		},
	}
	for _, tc := range cases {
		got, err := makeMethodRetType(tc.input)
		if err != nil {
			t.Errorf("makeMethodRetType got error, want nil: %v", err)
		}
		if got != tc.want {
			t.Errorf("makeMethodRetType faild, method name is %s\ngot %q, want %q", tc.input.Name, got, tc.want)
		}
	}
}

func TestMakeMethodArgs(t *testing.T) {
	cases := []struct {
		input introspect.Method
		want  []string
	}{
		{
			input: introspect.Method{
				Name: "simpleMethodWithOnlyOutputArg",
				Args: []introspect.MethodArg{
					{Name: "onlyOutput", Direction: "out", Type: "i"},
				},
				Annotations: []introspect.Annotation{
					{Name: "org.chromium.DBus.Method.Kind", Value: "simple"},
				},
			},
			want: nil,
		}, {
			input: introspect.Method{
				Name: "theOtherSimpleMethod",
				Args: []introspect.MethodArg{
					{Name: "x", Direction: "in", Type: "i"},
				},
				Annotations: []introspect.Annotation{
					{Name: "org.chromium.DBus.Method.Kind", Value: "simple"},
				},
			},
			want: []string{"int32_t in_x"},
		}, {
			input: introspect.Method{
				Name: "normalMethod",
				Annotations: []introspect.Annotation{
					{Name: "org.chromium.DBus.Method.Kind", Value: "normal"},
				},
			},
			want: []string{"brillo::ErrorPtr* error"},
		}, {
			input: introspect.Method{
				Name: "normalMethodIncludingMessage",
				Annotations: []introspect.Annotation{
					{Name: "org.chromium.DBus.Method.Kind", Value: "normal"},
					{Name: "org.chromium.DBus.Method.IncludeDBusMessage", Value: "true"},
				},
			},
			want: []string{"brillo::ErrorPtr* error", "dbus::Message* message"},
		}, {
			input: introspect.Method{
				Name: "asyncMethod",
				Args: []introspect.MethodArg{
					{Name: "x1", Direction: "out", Type: "h"},
					{Name: "x2",
						Direction: "out",
						Type:      "ay",
						Annotation: introspect.Annotation{
							Name:  "org.chromium.DBus.Argument.ProtobufClass",
							Value: "MyProtobufClass",
						},
					},
				},
				Annotations: []introspect.Annotation{
					{Name: "org.chromium.DBus.Method.Kind", Value: "async"},
				},
			},
			want: []string{"std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<base::ScopedFD, MyProtobufClass>> response"},
		}, {
			input: introspect.Method{
				Name: "asyncMethodWithNoArg",
				Annotations: []introspect.Annotation{
					{Name: "org.chromium.DBus.Method.Kind", Value: "async"},
				},
			},
			want: []string{"std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<>> response"},
		}, {
			input: introspect.Method{
				Name: "asyncMethodIncludingMessage",
				Args: []introspect.MethodArg{
					{Name: "x", Direction: "out", Type: "i"},
				},
				Annotations: []introspect.Annotation{
					{Name: "org.chromium.DBus.Method.Kind", Value: "async"},
					{Name: "org.chromium.DBus.Method.IncludeDBusMessage", Value: "true"},
				},
			},
			want: []string{
				"std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<int32_t>> response",
				"dbus::Message* message",
			},
		}, {
			input: introspect.Method{
				Name: "rawMethod",
				Args: []introspect.MethodArg{
					{Name: "x", Direction: "in", Type: "i"},
					{Name: "ret", Direction: "in", Type: "b"},
				},
				Annotations: []introspect.Annotation{
					{Name: "org.chromium.DBus.Method.Kind", Value: "raw"},
				},
			},
			want: []string{
				"dbus::MethodCall* method_call",
				"brillo::dbus_utils::ResponseSender sender",
			},
		}, {
			input: introspect.Method{
				Name: "methodWithArgs",
				Args: []introspect.MethodArg{
					{Name: "x1", Direction: "in", Type: "h"},
					{Name: "",
						Direction: "in",
						Type:      "ay",
						Annotation: introspect.Annotation{
							Name:  "org.chromium.DBus.Argument.ProtobufClass",
							Value: "MyProtobufClass",
						},
					},
					{Name: "x3", Direction: "out", Type: "h"},
					{Name: "",
						Direction: "out",
						Type:      "ay",
						Annotation: introspect.Annotation{
							Name:  "org.chromium.DBus.Argument.ProtobufClass",
							Value: "MyProtobufClass",
						},
					},
				},
				Annotations: []introspect.Annotation{
					{Name: "org.chromium.DBus.Method.Kind", Value: "simple"},
				},
			},
			want: []string{
				"const base::ScopedFD& in_x1", "const MyProtobufClass& in_2", "base::ScopedFD* out_x3", "MyProtobufClass* out_4",
			},
		},
	}
	for _, tc := range cases {
		got, err := makeMethodParams(tc.input)
		if err != nil {
			t.Errorf("makeMethodParams got error, want nil: %v", err)
		}
		if diff := cmp.Diff(got, tc.want); diff != "" {
			t.Errorf("makeMethodParams failed, method name is %s\n(-got +want):\n%s", tc.input.Name, diff)
		}
	}
}

func TestMakeSignalParams(t *testing.T) {
	cases := []struct {
		input introspect.Signal
		want  []string
	}{
		{
			input: introspect.Signal{
				Name: "sig1",
				Args: []introspect.SignalArg{
					{
						Name: "a1",
						Type: "h",
					}, {
						Name: "",
						Type: "ay",
						Annotation: introspect.Annotation{
							Name:  "org.chromium.DBus.Argument.ProtobufClass",
							Value: "MyProto",
						},
					},
				},
			},
			want: []string{
				"const base::ScopedFD& in_a1",
				"const MyProto& in_2",
			},
		}, {
			input: introspect.Signal{
				Name: "EmptySig",
				Args: nil,
			},
			want: nil,
		},
	}

	for _, tc := range cases {
		got, err := makeSignalParams(tc.input)
		if err != nil {
			t.Errorf("makeSignalParams got error, want nil: %v", err)
		}
		if diff := cmp.Diff(got, tc.want); diff != "" {
			t.Errorf("makeSignalParams failed, signal name is %s\n(-got +want):\n%s", tc.input.Name, diff)
		}
	}
}

func TestMakeDBusSignalParams(t *testing.T) {
	cases := []struct {
		input introspect.Signal
		want  []string
	}{
		{
			input: introspect.Signal{
				Name: "sig1",
				Args: []introspect.SignalArg{
					{
						Name: "a1",
						Type: "h",
					}, {
						Name: "",
						Type: "ay",
						Annotation: introspect.Annotation{
							Name:  "org.chromium.DBus.Argument.ProtobufClass",
							Value: "MyProto",
						},
					},
				},
			},
			want: []string{
				"base::ScopedFD /*a1*/",
				"MyProto",
			},
		}, {
			input: introspect.Signal{
				Name: "EmptySig",
				Args: nil,
			},
			want: nil,
		},
	}

	for _, tc := range cases {
		got, err := makeDBusSignalParams(tc.input)
		if err != nil {
			t.Errorf("makeDBusSignalParams got error, want nil: %v", err)
		}
		if diff := cmp.Diff(got, tc.want); diff != "" {
			t.Errorf("makeDBusSignalParams failed, signal name is %s\n(-got +want):\n%s", tc.input.Name, diff)
		}
	}
}
