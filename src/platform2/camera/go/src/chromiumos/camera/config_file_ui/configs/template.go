// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package configs

import (
	"encoding/json"
	"fmt"
	"html/template"
	"path"
	"path/filepath"
	"sort"
	"strconv"
)

// getMin is a template utility function to get the Min attribute in a
// NumberValueDescriptor.
func getMin(d interface{}) interface{} {
	switch v := d.(type) {
	case NumberValueDescriptor:
		return v.Min
	default:
		panic("Invalid ValueDescriptor")
	}
}

// getMax is a template utility function to get the Max attribute in a
// NumberValueDescriptor.
func getMax(d interface{}) interface{} {
	switch v := d.(type) {
	case NumberValueDescriptor:
		return v.Max
	default:
		panic("Invalid ValueDescriptor")
	}
}

// getStep is a template utility function to get the Step attribute in a
// NumberValueDescriptor.
func getStep(d interface{}) interface{} {
	switch v := d.(type) {
	case NumberValueDescriptor:
		return v.Step
	default:
		panic("Invalid ValueDescriptor")
	}
}

// getEnums is a template utility function to get the enum values in a
// SelectionValueDescriptor.
func getEnums(d interface{}) []Enum {
	switch v := d.(type) {
	case SelectionValueDescriptor:
		return v.Enums
	default:
		panic("Invalid ValueDescriptor")
	}
}

// getJS is a template utility function to get the JavaScript string as
// template.JS |d|.
func getJS(d interface{}) template.JS {
	if d == nil {
		panic("Input argument is nil")
	}
	var js []byte
	var err error
	switch casted := d.(type) {
	case map[string]interface{}:
		floatKeys := make(sort.Float64Slice, 0, len(casted))
		for k := range casted {
			val, err := strconv.ParseFloat(k, 64)
			if err != nil {
				// Cannot parse key into float64, fallback to
				// direct JSON unmarshalling.
				js, err = json.MarshalIndent(d, "", "  ")
				if err != nil {
					panic(err)
				}
				break
			}
			floatKeys = append(floatKeys, val)
		}
		sort.Float64s(floatKeys)
		js = append(js, []byte("{\n")...)
		for i, k := range floatKeys {
			strKey := fmt.Sprintf("%.0f", k)
			js = append(js, []byte(fmt.Sprintf("  %q: %v", strKey, casted[strKey]))...)
			if i < (len(floatKeys) - 1) {
				js = append(js, []byte(",")...)
			}
			js = append(js, []byte("\n")...)
		}
		js = append(js, []byte("}")...)

	default:
		js, err = json.Marshal(d)
		if err != nil {
			panic(err)
		}
	}
	return template.JS(js)
}

const tmplDir = "templates"

// LayoutTemplate returns a parsed template instance that can be used to
// generate a config settings UI.
func LayoutTemplate() *template.Template {
	layoutTmplFile := filepath.Join(tmplDir, "layout.tmpl")
	funcMap := template.FuncMap{
		"getmin":   getMin,
		"getmax":   getMax,
		"getstep":  getStep,
		"getenums": getEnums,
		"getjs":    getJS,
	}
	return template.Must(template.New(path.Base(layoutTmplFile)).Funcs(funcMap).ParseFiles(layoutTmplFile))
}
