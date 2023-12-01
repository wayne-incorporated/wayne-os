// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package introspect

import (
	"errors"
	"fmt"
)

// TODO(chromium:983008): Add validations for the type signatures.

// verifyIntrospection verifies that introspection does not contain invalid values.
func verifyIntrospection(i *Introspection) error {
	for _, itf := range i.Interfaces {
		if err := verifyInterface(&itf); err != nil {
			return fmt.Errorf("%s interface: %v", itf.Name, err)
		}
	}
	return nil
}

func verifyInterface(itf *Interface) error {
	if itf.Name == "" {
		return errors.New("empty interface name specified")
	}

	for _, m := range itf.Methods {
		if err := verifyMethod(&m); err != nil {
			return fmt.Errorf("%s method: %v", m.Name, err)
		}
	}
	// TODO(chromium:983008): Add validations for signals and properties.
	return nil
}

func verifyMethod(method *Method) error {
	if method.Name == "" {
		return errors.New("empty method name specified")
	}

	for _, arg := range method.Args {
		if err := verifyMethodArg(&arg); err != nil {
			return fmt.Errorf("%s argument: %v", arg.Name, err)
		}
	}

	// Verify that method annotation name is not duplicated.
	m := make(map[string]bool)
	for _, a := range method.Annotations {
		if !m[a.Name] {
			m[a.Name] = true
		} else {
			return fmt.Errorf("duplicate annotation %s", a.Name)
		}
	}

	for _, annotation := range method.Annotations {
		switch annotation.Name {
		case "org.chromium.DBus.Method.Kind":
			switch annotation.Value {
			case "simple", "normal", "async", "raw":
			default:
				return fmt.Errorf("invalid annotation value for %s", annotation.Name)
			}
		case "org.chromium.DBus.Method.Const":
			switch annotation.Value {
			case "true", "false":
			default:
				return fmt.Errorf("invalid annotation value for %s", annotation.Name)
			}
		case "org.chromium.DBus.Method.IncludeDBusMessage":
			switch annotation.Value {
			case "true", "false":
			default:
				return fmt.Errorf("invalid annotation value for %s", annotation.Name)
			}
		case "org.freedesktop.DBus.GLib.Async":
		}
	}

	return nil
}

// Note that the method argument name can be an empty string.
func verifyMethodArg(arg *MethodArg) error {
	if arg.Type == "" {
		return errors.New("empty argument type specified")
	}

	switch arg.Direction {
	case "in", "out", "":
	default:
		return fmt.Errorf("unknown method argument direction %s", arg.Direction)
	}

	switch arg.Annotation.Name {
	case "org.chromium.DBus.Argument.ProtobufClass":
		if arg.Type != "ay" {
			return fmt.Errorf("when using the %s annotation, the argument type must be %s", arg.Annotation.Name, "ay")
		}
	case "":
	}

	return nil
}
