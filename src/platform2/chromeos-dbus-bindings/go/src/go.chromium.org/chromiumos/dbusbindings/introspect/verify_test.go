// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package introspect

import "testing"

func TestInvalidInterfaceIntrospection(t *testing.T) {
	i := Introspection{
		Interfaces: []Interface{
			{
				Name: "itf",
				Methods: []Method{
					{
						Name: "f",
						Annotations: []Annotation{
							{Name: "org.chromium.DBus.Method.Kind"},
							{Name: "org.chromium.DBus.Method.Kind"},
						},
					},
				},
			},
		},
	}
	err := verifyIntrospection(&i)
	if err == nil {
		t.Fatal("verifyIntrospection unexpectedly succeeded")
	}
	const want = "itf interface: f method: duplicate annotation org.chromium.DBus.Method.Kind"
	if err.Error() != want {
		t.Errorf("verifyIntrospection err mismatch: got %q, want %q", err, want)
	}
}

func TestValidIntrospection(t *testing.T) {
	i := Introspection{
		Interfaces: []Interface{
			{Name: "emptyItf"},
		},
	}
	if err := verifyIntrospection(&i); err != nil {
		t.Errorf("verifyIntrospection got error, want nil: %q", err)
	}
}

func TestEmptyNameInterface(t *testing.T) {
	itf := Interface{Name: ""}
	err := verifyInterface(&itf)
	if err == nil {
		t.Fatal("verifyInterface unexpectedly succeeded")
	}
	const want = "empty interface name specified"
	if err.Error() != want {
		t.Errorf("verifyInterface err mismatch: got %q, want %q", err, want)
	}
}

func TestInvalidMethodInterface(t *testing.T) {
	itf := Interface{
		Name: "itf",
		Methods: []Method{
			{
				Name: "f",
				Annotations: []Annotation{
					{Name: "org.chromium.DBus.Method.Kind"},
					{Name: "org.chromium.DBus.Method.Kind"},
				},
			},
		},
	}
	err := verifyInterface(&itf)
	if err == nil {
		t.Fatal("verifyInterface unexpectedly succeeded")
	}
	const want = "f method: duplicate annotation org.chromium.DBus.Method.Kind"
	if err.Error() != want {
		t.Errorf("verifyInterface err mismatch: got %q, want %q", err, want)
	}
}

func TestValidInterface(t *testing.T) {
	itf := Interface{
		Name: "itf",
		Methods: []Method{
			{Name: "f"},
		},
	}
	if err := verifyInterface(&itf); err != nil {
		t.Errorf("verifyInterface got error, want nil: %q", err)
	}
}

func TestEmptyNameMethod(t *testing.T) {
	m := Method{Name: ""}
	err := verifyMethod(&m)
	if err == nil {
		t.Fatal("verifyMethod unexpectedly succeeded")
	}
	const want = "empty method name specified"
	if err.Error() != want {
		t.Errorf("verifyMethod err mismatch: got %q, want %q", err, want)
	}
}

func TestInvalidArgMethod(t *testing.T) {
	m := Method{
		Name: "f",
		Args: []MethodArg{
			{Name: "x"},
		},
	}
	err := verifyMethod(&m)
	if err == nil {
		t.Fatal("verifyMethod unexpectedly succeeded")
	}
	const want = "x argument: empty argument type specified"
	if err.Error() != want {
		t.Errorf("verifyMethod err mismatch: got %q, want %q", err, want)
	}
}

func TestDuplicatedAnnotationMethod(t *testing.T) {
	m := Method{
		Name: "f",
		Annotations: []Annotation{
			{Name: "org.chromium.DBus.Method.Kind"},
			{Name: "org.chromium.DBus.Method.Kind"},
		},
	}
	err := verifyMethod(&m)
	if err == nil {
		t.Fatal("verifyMethod unexpectedly succeeded")
	}
	const want = "duplicate annotation org.chromium.DBus.Method.Kind"
	if err.Error() != want {
		t.Errorf("verifyMethod err mismatch: got %q, want %q", err, want)
	}
}

func TestInvalidKindAnnotationMethod(t *testing.T) {
	m := Method{
		Name: "f",
		Annotations: []Annotation{
			{Name: "org.chromium.DBus.Method.Kind", Value: ""},
		},
	}
	err := verifyMethod(&m)
	if err == nil {
		t.Fatal("verifyMethod unexpectedly succeeded")
	}
	const want = "invalid annotation value for org.chromium.DBus.Method.Kind"
	if err.Error() != want {
		t.Errorf("verifyMethod err mismatch: got %q, want %q", err, want)
	}
}

func TestInvalidConstAnnotationMethod(t *testing.T) {
	m := Method{
		Name: "f",
		Annotations: []Annotation{
			{Name: "org.chromium.DBus.Method.Const", Value: ""},
		},
	}
	err := verifyMethod(&m)
	if err == nil {
		t.Fatal("verifyMethod unexpectedly succeeded")
	}
	const want = "invalid annotation value for org.chromium.DBus.Method.Const"
	if err.Error() != want {
		t.Errorf("verifyMethod err mismatch: got %q, want %q", err, want)
	}
}

func TestInvalidMessageAnnotationMethod(t *testing.T) {
	m := Method{
		Name: "f",
		Annotations: []Annotation{
			{Name: "org.chromium.DBus.Method.IncludeDBusMessage", Value: ""},
		},
	}
	err := verifyMethod(&m)
	if err == nil {
		t.Fatal("verifyMethod unexpectedly succeeded")
	}
	const want = "invalid annotation value for org.chromium.DBus.Method.IncludeDBusMessage"
	if err.Error() != want {
		t.Errorf("verifyMethod err mismatch: got %q, want %q", err, want)
	}
}

func TestValidMethod(t *testing.T) {
	m := Method{
		Name: "f",
		Args: []MethodArg{
			{Name: "n", Direction: "out", Type: "i"},
		},
		Annotations: []Annotation{
			{Name: "org.chromium.DBus.Method.Kind", Value: "simple"},
			{Name: "org.chromium.DBus.Method.Const", Value: "true"},
			{Name: "org.chromium.DBus.Method.IncludeDBusMessage", Value: "true"},
			{Name: "org.freedesktop.DBus.GLib.Async"},
			{Name: "ignored"},
		},
	}
	if err := verifyMethod(&m); err != nil {
		t.Errorf("verifyMethod got error, want nil: %q", err)
	}
}

func TestEmptyTypeArg(t *testing.T) {
	arg := MethodArg{Type: ""}
	err := verifyMethodArg(&arg)
	if err == nil {
		t.Fatal("verifyMethodArg unexpectedly succeeded")
	}
	const want = "empty argument type specified"
	if err.Error() != want {
		t.Errorf("verifyMethodArg err mismatch: got %q, want %q", err, want)
	}
}

func TestInvalidDirectionArg(t *testing.T) {
	arg := MethodArg{
		Type:      "s",
		Direction: "somewhere",
	}
	err := verifyMethodArg(&arg)
	if err == nil {
		t.Fatal("verifyMethodArg unexpectedly succeeded")
	}
	const want = "unknown method argument direction somewhere"
	if err.Error() != want {
		t.Errorf("verifyMethodArg err mismatch: got %q, want %q", err, want)
	}
}

func TestInvalidTypeArg(t *testing.T) {
	arg := MethodArg{
		Annotation: Annotation{Name: "org.chromium.DBus.Argument.ProtobufClass"},
		Type:       "TypeOtherThanAy",
	}
	err := verifyMethodArg(&arg)
	if err == nil {
		t.Fatal("verifyMethodArg unexpectedly succeeded")
	}
	const want = "when using the org.chromium.DBus.Argument.ProtobufClass annotation, the argument type must be ay"
	if err.Error() != want {
		t.Errorf("verifyMethodArg err mismatch: got %q, want %q", err, want)
	}
}

func TestValidArg(t *testing.T) {
	args := []MethodArg{
		{
			Name:      "n",
			Type:      "i",
			Direction: "in",
		}, {
			Type:       "ay",
			Direction:  "out",
			Annotation: Annotation{Name: "org.chromium.DBus.Argument.ProtobufClass"},
		}, {
			Type:       "s",
			Annotation: Annotation{Name: "ignored"},
		},
	}
	for _, arg := range args {
		if err := verifyMethodArg(&arg); err != nil {
			t.Errorf("verifyMethodArg got error, want nil: %q", err)
		}
	}
}
