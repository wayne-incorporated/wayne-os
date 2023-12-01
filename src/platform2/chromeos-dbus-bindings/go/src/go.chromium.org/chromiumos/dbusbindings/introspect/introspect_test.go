// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
package introspect_test

import (
	"testing"

	"go.chromium.org/chromiumos/dbusbindings/introspect"

	"github.com/google/go-cmp/cmp"
)

func TestInputArguments(t *testing.T) {
	m := introspect.Method{
		Name: "f",
		Args: []introspect.MethodArg{
			{Name: "x1", Direction: "in", Type: "i"},
			{Name: "x2", Direction: "", Type: "i"},
			{Name: "x3", Direction: "out", Type: "i"},
		},
	}
	got := m.InputArguments()
	want := []introspect.MethodArg{
		{Name: "x1", Direction: "in", Type: "i"},
		{Name: "x2", Direction: "", Type: "i"},
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("InputArguments failed (-got +want):\n%s", diff)
	}
}
func TestOutputArguments(t *testing.T) {
	m := introspect.Method{
		Name: "f",
		Args: []introspect.MethodArg{
			{Name: "x1", Direction: "in", Type: "i"},
			{Name: "x2", Direction: "", Type: "i"},
			{Name: "x3", Direction: "out", Type: "i"},
		},
	}
	got := m.OutputArguments()
	want := []introspect.MethodArg{
		{Name: "x3", Direction: "out", Type: "i"},
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("OutputArguments failed (-got +want):\n%s", diff)
	}
}
func TestKind(t *testing.T) {
	cases := []struct {
		input introspect.Method
		want  introspect.MethodKind
	}{
		{
			input: introspect.Method{
				Name: "f1",
				Annotations: []introspect.Annotation{
					{Name: "org.chromium.DBus.Method.Kind", Value: "simple"},
				},
			},
			want: introspect.MethodKindSimple,
		}, {
			input: introspect.Method{
				Name: "f2",
				Annotations: []introspect.Annotation{
					{Name: "org.chromium.DBus.Method.Kind", Value: "raw"},
				},
			},
			want: introspect.MethodKindRaw,
		}, {
			input: introspect.Method{
				Name: "f3",
				Annotations: []introspect.Annotation{
					{Name: "org.freedesktop.DBus.GLib.Async"},
				},
			},
			want: introspect.MethodKindAsync,
		}, {
			input: introspect.Method{
				Name: "f4",
			},
			want: introspect.MethodKindNormal,
		},
	}
	for _, tc := range cases {
		got := tc.input.Kind()
		if got != tc.want {
			t.Errorf("Kind faild, method name is %s\n got %q, want %q", tc.input.Name, got, tc.want)
		}
	}
}
func TestIncludeDBusMessage(t *testing.T) {
	cases := []struct {
		input introspect.Method
		want  bool
	}{
		{
			input: introspect.Method{
				Name: "f1",
				Annotations: []introspect.Annotation{
					{Name: "org.chromium.DBus.Method.IncludeDBusMessage", Value: "true"},
				},
			},
			want: true,
		}, {
			input: introspect.Method{
				Name: "f2",
				Annotations: []introspect.Annotation{
					{Name: "org.chromium.DBus.Method.IncludeDBusMessage", Value: "false"},
				},
			},
			want: false,
		}, {
			input: introspect.Method{
				Name: "f3",
			},
			want: false,
		},
	}
	for _, tc := range cases {
		got := tc.input.IncludeDBusMessage()
		if got != tc.want {
			t.Errorf("IncludeDBusMessage faild, method name is %s\n got %t, want %t", tc.input.Name, got, tc.want)
		}
	}
}
func TestConst(t *testing.T) {
	cases := []struct {
		input introspect.Method
		want  bool
	}{
		{
			input: introspect.Method{
				Name: "f1",
				Annotations: []introspect.Annotation{
					{Name: "org.chromium.DBus.Method.Const", Value: "true"},
				},
			},
			want: true,
		}, {
			input: introspect.Method{
				Name: "f2",
				Annotations: []introspect.Annotation{
					{Name: "org.chromium.DBus.Method.Const", Value: "false"},
				},
			},
			want: false,
		}, {
			input: introspect.Method{
				Name: "f3",
			},
			want: false,
		},
	}
	for _, tc := range cases {
		got := tc.input.Const()
		if got != tc.want {
			t.Errorf("Const faild, method name is %s\n got %t, want %t", tc.input.Name, got, tc.want)
		}
	}
}

func TestMethodArgMethods(t *testing.T) {
	cases := []struct {
		receiver   introspect.MethodArg
		BaseType   string
		InArgType  string
		OutArgType string
	}{
		{
			receiver: introspect.MethodArg{
				Name: "arg1",
				Type: "ay",
				Annotation: introspect.Annotation{
					Name:  "org.chromium.DBus.Argument.ProtobufClass",
					Value: "MyProtobufClass",
				},
			},
			BaseType:   "MyProtobufClass",
			InArgType:  "const MyProtobufClass&",
			OutArgType: "MyProtobufClass*",
		}, {
			receiver: introspect.MethodArg{
				Name: "arg2",
				Type: "h",
			},
			BaseType:   "base::ScopedFD",
			InArgType:  "const base::ScopedFD&",
			OutArgType: "base::ScopedFD*",
		},
	}

	for _, tc := range cases {
		got, err := tc.receiver.BaseType()
		if err != nil {
			t.Fatalf("Failed to get the base type of %q: %v", tc.receiver.Name, err)
		}
		if got != tc.BaseType {
			t.Fatalf("Unexpected base type of %q; want %s, got %s", tc.receiver.Name, tc.BaseType, got)
		}
		got, err = tc.receiver.InArgType()
		if err != nil {
			t.Fatalf("Failed to get the in arg type of %q: %v", tc.receiver.Name, err)
		}
		if got != tc.InArgType {
			t.Fatalf("Unexpected in arg type of %q; want %s, got %s", tc.receiver.Name, tc.InArgType, got)
		}
		got, err = tc.receiver.OutArgType()
		if err != nil {
			t.Fatalf("Failed to get the out arg type of %q: %v", tc.receiver.Name, err)
		}
		if got != tc.OutArgType {
			t.Fatalf("Unexpected out arg type of %q; want %s, got %s", tc.receiver.Name, tc.OutArgType, got)
		}
	}
}

func TestSignalArgMethods(t *testing.T) {
	cases := []struct {
		receiver   introspect.SignalArg
		BaseType   string
		InArgType  string
		OutArgType string
	}{
		{
			receiver: introspect.SignalArg{
				Name: "arg3",
				Type: "ay",
				Annotation: introspect.Annotation{
					Name:  "org.chromium.DBus.Argument.ProtobufClass",
					Value: "MyProtobufClass",
				},
			},
			BaseType:   "MyProtobufClass",
			InArgType:  "const MyProtobufClass&",
			OutArgType: "MyProtobufClass*",
		}, {
			receiver: introspect.SignalArg{
				Name: "arg4",
				Type: "h",
			},
			BaseType:   "base::ScopedFD",
			InArgType:  "const base::ScopedFD&",
			OutArgType: "base::ScopedFD*",
		},
	}

	for _, tc := range cases {
		got, err := tc.receiver.BaseType()
		if err != nil {
			t.Fatalf("Failed to get the base type of %q: %v", tc.receiver.Name, err)
		}
		if got != tc.BaseType {
			t.Fatalf("Unexpected base type of %q; want %s, got %s", tc.receiver.Name, tc.BaseType, got)
		}
		got, err = tc.receiver.InArgType()
		if err != nil {
			t.Fatalf("Failed to get the in arg type of %q: %v", tc.receiver.Name, err)
		}
		if got != tc.InArgType {
			t.Fatalf("Unexpected in arg type of %q; want %s, got %s", tc.receiver.Name, tc.InArgType, got)
		}
		got, err = tc.receiver.OutArgType()
		if err != nil {
			t.Fatalf("Failed to get the out arg type of %q: %v", tc.receiver.Name, err)
		}
		if got != tc.OutArgType {
			t.Fatalf("Unexpected out arg type of %q; want %s, got %s", tc.receiver.Name, tc.OutArgType, got)
		}
	}
}

func TestPropertyMethods(t *testing.T) {
	cases := []struct {
		receiver        introspect.Property
		BaseType        string
		InArgType       string
		OutArgType      string
		OutVariableName string
	}{
		{
			receiver: introspect.Property{
				Name: "property1",
				Type: "h",
			},
			BaseType:        "base::ScopedFD",
			InArgType:       "const base::ScopedFD&",
			OutArgType:      "base::ScopedFD*",
			OutVariableName: "property1",
		}, {
			receiver: introspect.Property{
				Name: "property1",
				Type: "h",
				Annotation: introspect.Annotation{
					Name:  "org.chromium.DBus.Argument.VariableName",
					Value: "property1_var",
				},
			},
			BaseType:        "base::ScopedFD",
			InArgType:       "const base::ScopedFD&",
			OutArgType:      "base::ScopedFD*",
			OutVariableName: "property1_var",
		},
	}

	for _, tc := range cases {
		got, err := tc.receiver.BaseType()
		if err != nil {
			t.Fatalf("Failed to get the base type of %q: %v", tc.receiver.Name, err)
		}
		if got != tc.BaseType {
			t.Fatalf("Unexpected base type of %q; want %s, got %s", tc.receiver.Name, tc.BaseType, got)
		}
		got, err = tc.receiver.InArgType()
		if err != nil {
			t.Fatalf("Failed to get the in arg type of %q: %v", tc.receiver.Name, err)
		}
		if got != tc.InArgType {
			t.Fatalf("Unexpected in arg type of %q; want %s, got %s", tc.receiver.Name, tc.InArgType, got)
		}
		got, err = tc.receiver.OutArgType()
		if err != nil {
			t.Fatalf("Failed to get the out arg type of %q: %v", tc.receiver.Name, err)
		}
		if got != tc.OutArgType {
			t.Fatalf("Unexpected out arg type of %q; want %s, got %s", tc.receiver.Name, tc.OutArgType, got)
		}

		got = tc.receiver.VariableName()
		if got != tc.OutVariableName {
			t.Fatalf("getting the variable name of %q failed; want %s, got %s", tc.receiver.Name, tc.OutVariableName, got)
		}
	}
}
