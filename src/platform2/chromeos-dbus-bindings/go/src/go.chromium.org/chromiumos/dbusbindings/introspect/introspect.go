// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Package introspect provides data type of introspection and its utility.
// Method and signal handlers are generated from introspection.
package introspect

import (
	"encoding/xml"
	"fmt"

	"go.chromium.org/chromiumos/dbusbindings/dbustype"
)

// TODO(chromium:983008): Add checks for the presence of unexpected elements in XML files.

// MethodKind is an enum to represent the kind of a method.
type MethodKind int

const (
	// MethodKindSimple indicates that the method doesn't fail and no brillo::ErrorPtr argument is given.
	MethodKindSimple MethodKind = iota

	// MethodKindNormal indicates that the method returns false and sets a brillo::ErrorPtr on failure.
	MethodKindNormal

	// MethodKindAsync indicates that instead of returning "out" arguments directly,
	// the method takes a DBusMethodResponse argument templated on the types of the "out" arguments.
	MethodKindAsync

	// MethodKindRaw indicates that the method takes a dbus::MethodCall and dbus::ExportedObject::ResponseSender
	// object directly.
	MethodKindRaw
)

// Annotation adds settings to MethodArg, SignalArg and Method.
type Annotation struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

// encoding/xml package cannot handle conflicting attributes
// in different namespaces, specificaly if one of them is root namespace. But we have such cases,
// e.g. a method argument may contain both type and tp:type, and we have to select type.
// cf: https://github.com/golang/go/issues/11724
// TODO(chromium:983008): Remove the workaround when go xml package is fixed.

// NonNamespaceString represents string of a XML tag in root namespace.
type NonNamespaceString string

// UnmarshalXMLAttr selects a XML tag in root namespace.
func (s *NonNamespaceString) UnmarshalXMLAttr(attr xml.Attr) error {
	if attr.Name.Space == "" {
		*s = NonNamespaceString(attr.Value)
	}
	return nil
}

// MethodArg represents method argument or return value.
type MethodArg struct {
	Name      string             `xml:"name,attr"`
	Type      NonNamespaceString `xml:"type,attr"`
	Direction string             `xml:"direction,attr"`
	// For now, MethodArg supports only ProtobufClass annotation only,
	// so it can have at most one annotation.
	Annotation Annotation `xml:"annotation"`
}

// TODO(chromium:983008): Remove the workaround for docstring tags that repeatedly appeared in
// lorgnette and hermes package.

// DocString represents a string of a document tag.
type DocString string

// UnmarshalText unmarshal all text even if it repeatedly appeared.
func (s *DocString) UnmarshalText(text []byte) error {
	*s += DocString(text)
	return nil
}

// Method represents method provided by a object through a interface.
// TODO(crbug.com/983008): Some xml files are missing tp namespace; add
// "http://telepathy.freedesktop.org/wiki/DbusSpec#extensions-v0" xml tag to DocString after
// fixing.
type Method struct {
	Name        string       `xml:"name,attr"`
	Args        []MethodArg  `xml:"arg"`
	Annotations []Annotation `xml:"annotation"`
	DocString   DocString    `xml:"docstring"`
}

// SignalArg represents signal message.
type SignalArg struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
	// For now, MethodArg supports only ProtobufClass annotation only,
	// so it can have at most one annotation.
	Annotation Annotation `xml:"annotation"`
}

// Signal represents signal provided by a object through a interface.
// TODO(crbug.com/983008): Some xml files are missing tp namespace; add
// "http://telepathy.freedesktop.org/wiki/DbusSpec#extensions-v0" xml tag to DocString after
// fixing.
type Signal struct {
	Name      string      `xml:"name,attr"`
	Args      []SignalArg `xml:"arg"`
	DocString DocString   `xml:"docstring"`
}

// Property represents property provided by a object through a interface.
// TODO(crbug.com/983008): Some xml files are missing tp namespace; add
// "http://telepathy.freedesktop.org/wiki/DbusSpec#extensions-v0" xml tag to DocString after
// fixing.
type Property struct {
	Name      string    `xml:"name,attr"`
	Type      string    `xml:"type,attr"`
	Access    string    `xml:"access,attr"`
	DocString DocString `xml:"docstring"`
	// For now, Property supports only VariableName annotation only,
	// so it can have at most one annotation.
	Annotation Annotation `xml:"annotation"`
}

// Interface represents interface provided by a object.
// TODO(crbug.com/983008): Some xml files are missing tp namespace; add
// "http://telepathy.freedesktop.org/wiki/DbusSpec#extensions-v0" xml tag to DocString after
// fixing.
type Interface struct {
	Name       string     `xml:"name,attr"`
	Methods    []Method   `xml:"method"`
	Signals    []Signal   `xml:"signal"`
	Properties []Property `xml:"property"`
	DocString  DocString  `xml:"docstring"`
}

// Introspection represents object specification required for generating
// method and signal handlers.
type Introspection struct {
	Name       string      `xml:"name,attr"`
	Interfaces []Interface `xml:"interface"`
}

// InputArguments returns the array of input arguments extracted from method arguments.
func (m *Method) InputArguments() []MethodArg {
	var ret []MethodArg
	for _, a := range m.Args {
		if a.Direction == "in" || a.Direction == "" { // default direction is "in"
			ret = append(ret, a)
		}
	}
	return ret
}

// OutputArguments returns the array of output arguments extracted from method arguments.
func (m *Method) OutputArguments() []MethodArg {
	var ret []MethodArg
	for _, a := range m.Args {
		if a.Direction == "out" {
			ret = append(ret, a)
		}
	}
	return ret
}

// Kind returns the kind of method.
func (m *Method) Kind() MethodKind {
	for _, a := range m.Annotations {
		// Support GLib.Async annotation as well.
		if a.Name == "org.freedesktop.DBus.GLib.Async" {
			return MethodKindAsync
		}

		if a.Name == "org.chromium.DBus.Method.Kind" {
			switch a.Value {
			case "simple":
				return MethodKindSimple
			case "normal":
				return MethodKindNormal
			case "async":
				return MethodKindAsync
			case "raw":
				return MethodKindRaw
			}
		}
	}

	return MethodKindNormal
}

// IncludeDBusMessage returns true if the method needs a message argument added.
func (m *Method) IncludeDBusMessage() bool {
	for _, a := range m.Annotations {
		if a.Name == "org.chromium.DBus.Method.IncludeDBusMessage" {
			return a.Value == "true"
		}
	}
	return false
}

// Const returns true if the method is a const member function.
func (m *Method) Const() bool {
	for _, a := range m.Annotations {
		if a.Name == "org.chromium.DBus.Method.Const" {
			return a.Value == "true"
		}
	}
	return false
}

// BaseType returns the C++ type corresponding to the type that the argument describes.
func (a *MethodArg) BaseType() (string, error) {
	return baseTypeInternal(string(a.Type), &a.Annotation)
}

// InArgType returns the C++ type corresponding to the type that the argument describes
// for an in argument.
func (a *MethodArg) InArgType() (string, error) {
	return inArgTypeInternal(string(a.Type), &a.Annotation)
}

// OutArgType returns the C++ type corresponding to the type that the argument describes
// for an out argument.
func (a *MethodArg) OutArgType() (string, error) {
	return outArgTypeInternal(string(a.Type), &a.Annotation)
}

// CallbackType returns the C++ type to be used as a callback's argument.
func (a *MethodArg) CallbackType() (string, error) {
	// This is workaround to deal with current function layering structure.
	// TODO(crbug.com/983008): Cleans up the implementation by moving
	// receiver concept up to here.
	return a.InArgType()
}

// BaseType returns the C++ type corresponding to the type that the argument describes.
func (a *SignalArg) BaseType() (string, error) {
	return baseTypeInternal(a.Type, &a.Annotation)
}

// InArgType returns the C++ type corresponding to the type that the argument describes
// for an in argument.
func (a *SignalArg) InArgType() (string, error) {
	return inArgTypeInternal(a.Type, &a.Annotation)
}

// OutArgType returns the C++ type corresponding to the type that the argument describes
// for an out argument.
func (a *SignalArg) OutArgType() (string, error) {
	return outArgTypeInternal(a.Type, &a.Annotation)
}

// CallbackType returns the C++ type to be used as a callback's argument.
func (a *SignalArg) CallbackType() (string, error) {
	// This is workaround to deal with current function layering structure.
	// TODO(crbug.com/983008): Cleans up the implementation by moving
	// receiver concept up to here.
	return a.InArgType()
}

// BaseType returns the C++ type corresponding to the type that the property describes.
func (p *Property) BaseType() (string, error) {
	return baseTypeInternal(p.Type, nil)
}

// InArgType returns the C++ type corresponding to the type that the property describes
// for an in argument.
func (p *Property) InArgType() (string, error) {
	return inArgTypeInternal(p.Type, nil)
}

// OutArgType returns the C++ type corresponding to the type that the property describes
// for an out argument.
func (p *Property) OutArgType() (string, error) {
	return outArgTypeInternal(p.Type, nil)
}

// VariableName returns annotation value as variable name if the property has
// annotation of VariableName. Otherwise returns property name.
func (p *Property) VariableName() string {
	if p.Annotation.Name == "org.chromium.DBus.Argument.VariableName" {
		return p.Annotation.Value
	}
	return p.Name
}

func baseTypeInternal(s string, a *Annotation) (string, error) {
	// chromeos-dbus-binding supports native protobuf types.
	if a != nil && a.Name == "org.chromium.DBus.Argument.ProtobufClass" {
		return a.Value, nil
	}

	typ, err := dbustype.Parse(s)
	if err != nil {
		return "", err
	}
	return typ.BaseType(), nil
}

func inArgTypeInternal(s string, a *Annotation) (string, error) {
	// chromeos-dbus-binding supports native protobuf types.
	if a != nil && a.Name == "org.chromium.DBus.Argument.ProtobufClass" {
		return fmt.Sprintf("const %s&", a.Value), nil
	}

	typ, err := dbustype.Parse(s)
	if err != nil {
		return "", err
	}
	return typ.InArgType(), nil
}

func outArgTypeInternal(s string, a *Annotation) (string, error) {
	// chromeos-dbus-binding supports native protobuf types.
	if a != nil && a.Name == "org.chromium.DBus.Argument.ProtobufClass" {
		return fmt.Sprintf("%s*", a.Value), nil
	}

	typ, err := dbustype.Parse(s)
	if err != nil {
		return "", err
	}
	return typ.OutArgType(), nil
}
