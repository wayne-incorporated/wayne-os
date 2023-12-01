// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Tests for scanner_capabilities_utils.go.

package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// Well-formatted XML test data.
const XMLTestData = `<scan:ScannerCapabilities xmlns:pwg="http://www.pwg.org/schemas/2010/12/sm" xmlns:scan="http://schemas.hp.com/imaging/escl/2011/05/03">
	<pwg:Version>2.63</pwg:Version>
	<pwg:MakeAndModel>MF741C/743C</pwg:MakeAndModel>
	<pwg:SerialNumber>TestSerialNumber</pwg:SerialNumber>
	<scan:Manufacturer>Canon</scan:Manufacturer>
	<scan:UUID>TestUuid</scan:UUID>
	<scan:AdminURI>TestAdminURI</scan:AdminURI>
	<scan:IconURI>TestIconURI</scan:IconURI>
	<scan:SettingProfiles>
		<scan:SettingProfile name="p1">
			<scan:ColorModes>
				<scan:ColorMode>BlackAndWhite1</scan:ColorMode>
			</scan:ColorModes>
			<scan:DocumentFormats>
				<pwg:DocumentFormat>image/jpeg</pwg:DocumentFormat>
				<pwg:DocumentFormat>application/pdf</pwg:DocumentFormat>
				<scan:DocumentFormatExt>image/jpeg</scan:DocumentFormatExt>
				<scan:DocumentFormatExt>application/pdf</scan:DocumentFormatExt>
			</scan:DocumentFormats>
			<scan:SupportedResolutions>
				<scan:DiscreteResolutions>
					<scan:DiscreteResolution>
						<scan:XResolution>100</scan:XResolution>
						<scan:YResolution>200</scan:YResolution>
					</scan:DiscreteResolution>
					<scan:DiscreteResolution>
						<scan:XResolution>300</scan:XResolution>
						<scan:YResolution>300</scan:YResolution>
					</scan:DiscreteResolution>
				</scan:DiscreteResolutions>
			</scan:SupportedResolutions>
			<scan:ColorSpaces>
				<scan:ColorSpace>RGB</scan:ColorSpace>
			</scan:ColorSpaces>
			<scan:CcdChannels>
				<scan:CcdChannel scan:default="true">Red</scan:CcdChannel>
				<scan:CcdChannel>Green</scan:CcdChannel>
			</scan:CcdChannels>
			<scan:BinaryRenderings>
				<scan:BinaryRendering>Threshold</scan:BinaryRendering>
				<scan:BinaryRendering scan:default="true">Halftone</scan:BinaryRendering>
			</scan:BinaryRenderings>
		</scan:SettingProfile>
	</scan:SettingProfiles>
	<scan:Platen>
		<scan:PlatenInputCaps>
			<scan:MinWidth>16</scan:MinWidth>
			<scan:MaxWidth>1200</scan:MaxWidth>
			<scan:MinHeight>32</scan:MinHeight>
			<scan:MaxHeight>2800</scan:MaxHeight>
			<scan:MaxScanRegions>2</scan:MaxScanRegions>
			<scan:MaxOpticalXResolution>800</scan:MaxOpticalXResolution>
			<scan:MaxOpticalYResolution>1200</scan:MaxOpticalYResolution>
			<scan:MaxPhysicalWidth>1200</scan:MaxPhysicalWidth>
			<scan:MaxPhysicalHeight>2800</scan:MaxPhysicalHeight>
			<scan:SettingProfiles>
				<scan:SettingProfile>
					<scan:ColorModes>
						<scan:ColorMode>RGB24</scan:ColorMode>
					</scan:ColorModes>
					<scan:DocumentFormats>
						<pwg:DocumentFormat>application/octet-stream</pwg:DocumentFormat>
					</scan:DocumentFormats>
					<scan:SupportedResolutions>
						<scan:ResolutionRange>
							<scan:XResolutionRange>
								<scan:Min>75</scan:Min>
								<scan:Max>800</scan:Max>
								<scan:Normal>300</scan:Normal>
								<scan:Step>10</scan:Step>
							</scan:XResolutionRange>
							<scan:YResolutionRange>
								<scan:Min>150</scan:Min>
								<scan:Max>1200</scan:Max>
								<scan:Normal>600</scan:Normal>
								<scan:Step>50</scan:Step>
							</scan:YResolutionRange>
						</scan:ResolutionRange>
					</scan:SupportedResolutions>
					<scan:ColorSpaces>
						<scan:ColorSpace>RGB</scan:ColorSpace>
					</scan:ColorSpaces>
					<scan:CcdChannels>
						<scan:CcdChannel>Blue</scan:CcdChannel>
					</scan:CcdChannels>
				</scan:SettingProfile>
			</scan:SettingProfiles>
			<scan:SupportedIntents>
				<scan:Intent>Document</scan:Intent>
				<scan:Intent>Photo</scan:Intent>
			</scan:SupportedIntents>
			<scan:EdgeAutoDetection>
				<scan:SupportedEdge>TopEdge</scan:SupportedEdge>
				<scan:SupportedEdge>BottomEdge</scan:SupportedEdge>
			</scan:EdgeAutoDetection>
			<scan:RiskyLeftMargin>28</scan:RiskyLeftMargin>
			<scan:RiskyRightMargin>30</scan:RiskyRightMargin>
			<scan:RiskyTopMargin>32</scan:RiskyTopMargin>
			<scan:RiskyBottomMargin>44</scan:RiskyBottomMargin>
		</scan:PlatenInputCaps>
	</scan:Platen>
	<scan:Adf>
		<scan:AdfSimplexInputCaps>
			<scan:MinWidth>32</scan:MinWidth>
			<scan:MaxWidth>2551</scan:MaxWidth>
			<scan:MinHeight>32</scan:MinHeight>
			<scan:MaxHeight>4200</scan:MaxHeight>
			<scan:MaxScanRegions>1</scan:MaxScanRegions>
			<scan:MaxOpticalXResolution>300</scan:MaxOpticalXResolution>
			<scan:MaxOpticalYResolution>300</scan:MaxOpticalYResolution>
			<scan:MaxPhysicalWidth>2551</scan:MaxPhysicalWidth>
			<scan:MaxPhysicalHeight>4200</scan:MaxPhysicalHeight>
			<scan:SettingProfiles>
				<scan:SettingProfile ref="p1"/>
			</scan:SettingProfiles>
			<scan:SupportedIntents>
				<scan:Intent>Document</scan:Intent>
			</scan:SupportedIntents>
		</scan:AdfSimplexInputCaps>
		<scan:AdfDuplexInputCaps>
			<scan:MinWidth>32</scan:MinWidth>
			<scan:MaxWidth>2551</scan:MaxWidth>
			<scan:MinHeight>32</scan:MinHeight>
			<scan:MaxHeight>4200</scan:MaxHeight>
			<scan:MaxScanRegions>1</scan:MaxScanRegions>
			<scan:MaxOpticalXResolution>300</scan:MaxOpticalXResolution>
			<scan:MaxOpticalYResolution>300</scan:MaxOpticalYResolution>
			<scan:MaxPhysicalWidth>2551</scan:MaxPhysicalWidth>
			<scan:MaxPhysicalHeight>4200</scan:MaxPhysicalHeight>
			<scan:SettingProfiles>
				<scan:SettingProfile ref="p1"/>
			</scan:SettingProfiles>
			<scan:SupportedIntents>
				<scan:Intent>Photo</scan:Intent>
			</scan:SupportedIntents>
		</scan:AdfDuplexInputCaps>
		<scan:FeederCapacity>100</scan:FeederCapacity>
		<scan:Justification>
			<pwg:XImagePosition>Center</pwg:XImagePosition>
			<pwg:YImagePosition>Top</pwg:YImagePosition>
		</scan:Justification>
		<scan:AdfOptions>
			<scan:AdfOption>DetectPaperLoaded</scan:AdfOption>
			<scan:AdfOption>Duplex</scan:AdfOption>
		</scan:AdfOptions>
	</scan:Adf>
	<scan:StoredJobRequestSupport>
		<scan:MaxStoredJobRequests>10</scan:MaxStoredJobRequests>
		<scan:TimeoutInSeconds>120</scan:TimeoutInSeconds>
		<scan:PINLength>4</scan:PINLength>
		<scan:MaxJobNameLength>256</scan:MaxJobNameLength>
	</scan:StoredJobRequestSupport>
	<scan:BlankPageDetection>true</scan:BlankPageDetection>
	<scan:BlankPageDetectionAndRemoval>true</scan:BlankPageDetectionAndRemoval>
</scan:ScannerCapabilities>`

// XML test data which references a SettingProfile which does not exist.
const noReferencedProfileXMLTestData = `<scan:ScannerCapabilities xmlns:pwg="http://www.pwg.org/schemas/2010/12/sm" xmlns:scan="http://schemas.hp.com/imaging/escl/2011/05/03">
	<pwg:Version>2.63</pwg:Version>
	<pwg:MakeAndModel>MF741C/743C</pwg:MakeAndModel>
	<pwg:SerialNumber>TestSerialNumber</pwg:SerialNumber>
	<scan:Manufacturer>Canon</scan:Manufacturer>
	<scan:UUID>TestUUID</scan:UUID>
	<scan:AdminURI>TestAdminURI</scan:AdminURI>
	<scan:IconURI>TestIconURI</scan:IconURI>
	<scan:Platen>
		<scan:PlatenInputCaps>
			<scan:MinWidth>16</scan:MinWidth>
			<scan:MaxWidth>1200</scan:MaxWidth>
			<scan:MinHeight>32</scan:MinHeight>
			<scan:MaxHeight>2800</scan:MaxHeight>
			<scan:MaxScanRegions>2</scan:MaxScanRegions>
			<scan:MaxOpticalXResolution>800</scan:MaxOpticalXResolution>
			<scan:MaxOpticalYResolution>1200</scan:MaxOpticalYResolution>
			<scan:MaxPhysicalWidth>1200</scan:MaxPhysicalWidth>
			<scan:MaxPhysicalHeight>2800</scan:MaxPhysicalHeight>
			<scan:SettingProfiles>
				<scan:SettingProfile ref="p1"/>
			</scan:SettingProfiles>
			<scan:SupportedIntents>
				<scan:Intent>Document</scan:Intent>
				<scan:Intent>Photo</scan:Intent>
			</scan:SupportedIntents>
			<scan:EdgeAutoDetection>
				<scan:SupportedEdge>TopEdge</scan:SupportedEdge>
				<scan:SupportedEdge>BottomEdge</scan:SupportedEdge>
			</scan:EdgeAutoDetection>
			<scan:RiskyLeftMargin>28</scan:RiskyLeftMargin>
			<scan:RiskyRightMargin>30</scan:RiskyRightMargin>
			<scan:RiskyTopMargin>32</scan:RiskyTopMargin>
			<scan:RiskyBottomMargin>44</scan:RiskyBottomMargin>
		</scan:PlatenInputCaps>
	</scan:Platen>
</scan:ScannerCapabilities>`

// XML test data which is not valid XML.
const badXMLTestData = `<scan:ScannerCapabilities`

// Well-formatted test data from lorgnette_cli.
const lorgnetteCLITestData = `{
"SOURCE_ADF_DUPLEX":{
	"ColorModes":["MODE_COLOR"],
	"Name":"ADF Duplex",
	"Resolutions":[150],
	"ScannableArea":{"Height":400,"Width":120}},
"SOURCE_ADF_SIMPLEX":{
	"ColorModes":["MODE_LINEART"],
	"Name":"ADF","Resolutions":[200,600],
	"ScannableArea":{"Height":200,"Width":100}},
"SOURCE_PLATEN":{
	"ColorModes":["MODE_COLOR","MODE_GRAYSCALE"],
	"Name":"Flatbed","Resolutions":[300],
	"ScannableArea":{"Height":355.59999084472656,"Width":215.9846649169922}}
}`

// Test data from lorgnette_cli which is not valid JSON data.
const badJSONlorgnetteCLITestData = `{"SOURCE_ADF_DUPLEX":{"ColorModes":`

// prettyFormatStruct formats a struct as JSON for human-readability.
func prettyFormatStruct(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", " ")
	return string(s)
}

// TestGetScannerCapabilities tests that a scanner capabilities response can be
// parsed successfully.
func TestGetScannerCapabilities(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, XMLTestData)
	}))
	defer ts.Close()

	got, err := GetScannerCapabilities(LorgnetteScannerInfo{Protocol: "airscan", Address: ts.URL})

	if err != nil {
		t.Error(err)
	}

	want := ScannerCapabilities{
		Version:      "2.63",
		MakeAndModel: "MF741C/743C",
		Manufacturer: "Canon",
		SettingProfiles: []SettingProfile{
			SettingProfile{
				Name:               "p1",
				Ref:                "",
				ColorModes:         []string{"BlackAndWhite1"},
				DocumentFormats:    []string{"image/jpeg", "application/pdf"},
				DocumentFormatsExt: []string{"image/jpeg", "application/pdf"},
				SupportedResolutions: SupportedResolutions{
					DiscreteResolutions: []DiscreteResolution{
						DiscreteResolution{
							XResolution: 100,
							YResolution: 200},
						DiscreteResolution{
							XResolution: 300,
							YResolution: 300}},
					XResolutionRange: ResolutionRange{
						Min:    0,
						Max:    0,
						Normal: 0,
						Step:   0},
					YResolutionRange: ResolutionRange{
						Min:    0,
						Max:    0,
						Normal: 0,
						Step:   0}}}},
		PlatenInputCaps: SourceCapabilities{
			MaxWidth:       1200,
			MinWidth:       16,
			MaxHeight:      2800,
			MinHeight:      32,
			MaxScanRegions: 2,
			SettingProfile: SettingProfile{
				Name:            "",
				Ref:             "",
				ColorModes:      []string{"RGB24"},
				DocumentFormats: []string{"application/octet-stream"},
				SupportedResolutions: SupportedResolutions{
					XResolutionRange: ResolutionRange{
						Min:    75,
						Max:    800,
						Normal: 300,
						Step:   10},
					YResolutionRange: ResolutionRange{
						Min:    150,
						Max:    1200,
						Normal: 600,
						Step:   50}}},
			MaxOpticalXResolution: 800,
			MaxOpticalYResolution: 1200,
			MaxPhysicalWidth:      1200,
			MaxPhysicalHeight:     2800},
		AdfCapabilities: AdfCapabilities{
			AdfSimplexInputCaps: SourceCapabilities{
				MaxWidth:       2551,
				MinWidth:       32,
				MaxHeight:      4200,
				MinHeight:      32,
				MaxScanRegions: 1,
				SettingProfile: SettingProfile{
					Name:               "p1",
					Ref:                "",
					ColorModes:         []string{"BlackAndWhite1"},
					DocumentFormats:    []string{"image/jpeg", "application/pdf"},
					DocumentFormatsExt: []string{"image/jpeg", "application/pdf"},
					SupportedResolutions: SupportedResolutions{
						DiscreteResolutions: []DiscreteResolution{
							DiscreteResolution{
								XResolution: 100,
								YResolution: 200},
							DiscreteResolution{
								XResolution: 300,
								YResolution: 300}},
						XResolutionRange: ResolutionRange{
							Min:    0,
							Max:    0,
							Normal: 0,
							Step:   0},
						YResolutionRange: ResolutionRange{
							Min:    0,
							Max:    0,
							Normal: 0,
							Step:   0}}},
				MaxOpticalXResolution: 300,
				MaxOpticalYResolution: 300,
				MaxPhysicalWidth:      2551,
				MaxPhysicalHeight:     4200},
			AdfDuplexInputCaps: SourceCapabilities{
				MaxWidth:       2551,
				MinWidth:       32,
				MaxHeight:      4200,
				MinHeight:      32,
				MaxScanRegions: 1,
				SettingProfile: SettingProfile{
					Name:               "p1",
					Ref:                "",
					ColorModes:         []string{"BlackAndWhite1"},
					DocumentFormats:    []string{"image/jpeg", "application/pdf"},
					DocumentFormatsExt: []string{"image/jpeg", "application/pdf"},
					SupportedResolutions: SupportedResolutions{
						DiscreteResolutions: []DiscreteResolution{
							DiscreteResolution{
								XResolution: 100,
								YResolution: 200},
							DiscreteResolution{
								XResolution: 300,
								YResolution: 300}},
						XResolutionRange: ResolutionRange{
							Min:    0,
							Max:    0,
							Normal: 0,
							Step:   0},
						YResolutionRange: ResolutionRange{
							Min:    0,
							Max:    0,
							Normal: 0,
							Step:   0}}},
				MaxOpticalXResolution: 300,
				MaxOpticalYResolution: 300,
				MaxPhysicalWidth:      2551,
				MaxPhysicalHeight:     4200},
			AdfOptions: []string{"DetectPaperLoaded", "Duplex"}},
		CameraInputCaps: SourceCapabilities{
			MaxWidth:       0,
			MinWidth:       0,
			MaxHeight:      0,
			MinHeight:      0,
			MaxScanRegions: 0,
			SettingProfile: SettingProfile{
				Name: "",
				Ref:  "",
				SupportedResolutions: SupportedResolutions{
					XResolutionRange: ResolutionRange{
						Min:    0,
						Max:    0,
						Normal: 0,
						Step:   0},
					YResolutionRange: ResolutionRange{
						Min:    0,
						Max:    0,
						Normal: 0,
						Step:   0}}},
			MaxOpticalXResolution: 0,
			MaxOpticalYResolution: 0,
			MaxPhysicalWidth:      0,
			MaxPhysicalHeight:     0},
		StoredJobRequestSupport: StoredJobRequestSupport{
			MaxStoredJobRequests: 10,
			TimeoutInSeconds:     120,
			PINLength:            4,
			MaxJobNameLength:     256}}

	if !cmp.Equal(want, got) {
		// For such long structs, it's easier to compare if they're
		// pretty-printed.
		t.Errorf("Expected: %s, got: %s", prettyFormatStruct(want), prettyFormatStruct(got))
	}
}

// TestGetScannerCapabilitiesNotReferencedProfile tests that an input
// capabilities object which references a SettingProfile which does exist fails
// to parse.
func TestGetScannerCapabilitiesNotReferencedProfile(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, noReferencedProfileXMLTestData)
	}))
	defer ts.Close()

	_, err := GetScannerCapabilities(LorgnetteScannerInfo{Protocol: "airscan", Address: ts.URL})

	if err == nil {
		t.Error("Expected error from referenced profile not existing")
	}
}

// TestGetScannerCapabilitiesBadHttpResponse tests that a bad HTTP response is
// caught.
func TestGetScannerCapabilitiesBadHttpResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, XMLTestData)
	}))
	defer ts.Close()

	_, err := GetScannerCapabilities(LorgnetteScannerInfo{Protocol: "airscan", Address: ts.URL})

	if err == nil {
		t.Error("Expected error from bad HTTP response status")
	}
}

// TestGetScannerCapabilitiesBadXml tests that a bad XML response is caught.
func TestGetScannerCapabilitiesBadXml(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, badXMLTestData)
	}))
	defer ts.Close()

	_, err := GetScannerCapabilities(LorgnetteScannerInfo{Protocol: "airscan", Address: ts.URL})

	if err == nil {
		t.Error("Expected error from bad XML")
	}
}

// TestParseLorgnetteCapabilities tests that JSON data can be parsed into
// LorgnetteCapabilities.
func TestParseLorgnetteCapabilities(t *testing.T) {
	got, err := ParseLorgnetteCapabilities(lorgnetteCLITestData)

	if err != nil {
		t.Error(err)
	}

	want := LorgnetteCapabilities{
		PlatenCaps: LorgnetteSource{
			ColorModes: []string{
				"MODE_COLOR",
				"MODE_GRAYSCALE"},
			Resolutions: []int{
				300},
			ScannableArea: ScannableArea{
				Height: 355.59999084472656,
				Width:  215.9846649169922}},
		AdfSimplexCaps: LorgnetteSource{
			ColorModes: []string{
				"MODE_LINEART"},
			Resolutions: []int{
				200,
				600},
			ScannableArea: ScannableArea{
				Height: 200,
				Width:  100}},
		AdfDuplexCaps: LorgnetteSource{
			ColorModes: []string{
				"MODE_COLOR"},
			Resolutions: []int{
				150},
			ScannableArea: ScannableArea{
				Height: 400,
				Width:  120}}}

	if !cmp.Equal(want, got) {
		// For such long structs, it's easier to compare if they're
		// pretty-printed.
		t.Errorf("Expected: %s, got: %s", prettyFormatStruct(want), prettyFormatStruct(got))
	}

}

// TestParseLorgnetteCapabilitiesBadJSON tests that incorrectly formatted JSON
// data is caught.
func TestParseLorgnetteCapabilitiesBadJSON(t *testing.T) {
	_, err := ParseLorgnetteCapabilities(badJSONlorgnetteCLITestData)

	if err == nil {
		t.Error("Expected error from bad JSON")
	}

}

// TestIsPopulatedLorgnetteSource tests that the IsPopulated function works
// correctly on lorgnette sources.
func TestIsPopulatedLorgnetteSource(t *testing.T) {
	tests := []struct {
		source LorgnetteSource
		ret    bool
	}{
		{
			source: LorgnetteSource{
				ColorModes:  []string{"MODE_COLOR", "MODE_GRAYSCALE"},
				Resolutions: []int{75, 150, 300},
				ScannableArea: ScannableArea{
					Height: 355.59998,
					Width:  215.98466}},
			ret: true,
		},
		{
			source: LorgnetteSource{},
			ret:    false,
		},
	}

	for _, tc := range tests {
		got := tc.source.IsPopulated()

		if got != tc.ret {
			t.Errorf("Expected %t, got %t for source: %v", tc.ret, got, tc.source)
		}
	}
}

// TestIsPopulatedSourceCapabilities tests that the IsPopulated function works
// correctly on source capabilities.
func TestIsPopulatedSourceCapabilities(t *testing.T) {
	tests := []struct {
		caps SourceCapabilities
		ret  bool
	}{
		{
			caps: SourceCapabilities{
				MaxWidth:       1200,
				MinWidth:       16,
				MaxHeight:      2800,
				MinHeight:      32,
				MaxScanRegions: 2,
				SettingProfile: SettingProfile{
					Name:            "",
					Ref:             "",
					ColorModes:      []string{"RGB24"},
					DocumentFormats: []string{"application/octet-stream"},
					SupportedResolutions: SupportedResolutions{
						XResolutionRange: ResolutionRange{
							Min:    65,
							Max:    85,
							Normal: 75,
							Step:   10},
						YResolutionRange: ResolutionRange{
							Min:    60,
							Max:    105,
							Normal: 90,
							Step:   15}}},
				MaxOpticalXResolution: 85,
				MaxOpticalYResolution: 105,
				MaxPhysicalWidth:      1200,
				MaxPhysicalHeight:     2800},
			ret: true,
		},
		{
			caps: SourceCapabilities{},
			ret:  false,
		},
	}

	for _, tc := range tests {
		got := tc.caps.IsPopulated()

		if got != tc.ret {
			t.Errorf("Expected %t, got %t for caps: %v", tc.ret, got, tc.caps)
		}
	}
}

// TestToLorgnetteResolutions tests that the ToLorgnetteResolutions function
// works correctly.
func TestToLorgnetteResolutions(t *testing.T) {
	tests := []struct {
		resolutions          SupportedResolutions
		lorgnetteResolutions []int
	}{
		{
			resolutions: SupportedResolutions{
				XResolutionRange: ResolutionRange{
					Min:    75,
					Max:    600,
					Normal: 300,
					Step:   25},
				YResolutionRange: ResolutionRange{
					Min:    75,
					Max:    600,
					Normal: 300,
					Step:   5}},
			lorgnetteResolutions: []int{75, 100, 150, 200, 300, 600},
		},
		{
			resolutions: SupportedResolutions{
				DiscreteResolutions: []DiscreteResolution{
					DiscreteResolution{
						XResolution: 75,
						YResolution: 75,
					},
					DiscreteResolution{
						XResolution: 100,
						YResolution: 100,
					},
					DiscreteResolution{
						XResolution: 150,
						YResolution: 150,
					},
					DiscreteResolution{
						XResolution: 200,
						YResolution: 200,
					},
					DiscreteResolution{
						XResolution: 300,
						YResolution: 300,
					},
					DiscreteResolution{
						XResolution: 600,
						YResolution: 600,
					},
				}},
			lorgnetteResolutions: []int{75, 100, 150, 200, 300, 600},
		},
		{
			resolutions: SupportedResolutions{
				XResolutionRange: ResolutionRange{
					Min:    0,
					Max:    225,
					Normal: 150,
					Step:   75},
				YResolutionRange: ResolutionRange{
					Min:    0,
					Max:    700,
					Normal: 300,
					Step:   100}},
		},
		{
			resolutions: SupportedResolutions{
				DiscreteResolutions: []DiscreteResolution{
					DiscreteResolution{
						XResolution: 50,
						YResolution: 50,
					},
					DiscreteResolution{
						XResolution: 125,
						YResolution: 125,
					},
					DiscreteResolution{
						XResolution: 1200,
						YResolution: 1200,
					},
					DiscreteResolution{
						XResolution: 200,
						YResolution: 300,
					},
					DiscreteResolution{
						XResolution: 300,
						YResolution: 200,
					},
				}},
		},
		{
			resolutions: SupportedResolutions{},
		},
	}

	for _, tc := range tests {
		got := tc.resolutions.ToLorgnetteResolutions()

		if !cmp.Equal(got, tc.lorgnetteResolutions) {
			t.Errorf("Expected %v, got %v for resolutions: %v", tc.lorgnetteResolutions, got, tc.resolutions)
		}
	}
}

// TestToLorgnetteSource tests that the ToLorgnetteSource function works
// correctly.
func TestToLorgnetteSource(t *testing.T) {
	tests := []struct {
		caps            SourceCapabilities
		lorgnetteSource LorgnetteSource
	}{
		{
			caps: SourceCapabilities{
				MaxWidth:  2551,
				MaxHeight: 4200,
				SettingProfile: SettingProfile{
					ColorModes: []string{"BlackAndWhite1", "Grayscale8", "Grayscale16", "RGB24", "RGB48"},
					SupportedResolutions: SupportedResolutions{
						XResolutionRange: ResolutionRange{
							Min:    75,
							Max:    600,
							Normal: 75,
							Step:   25},
						YResolutionRange: ResolutionRange{
							Min:    60,
							Max:    700,
							Normal: 90,
							Step:   5}}}},
			lorgnetteSource: LorgnetteSource{
				ColorModes:  []string{"MODE_GRAYSCALE", "MODE_UNSPECIFIED", "MODE_COLOR", "MODE_UNSPECIFIED"},
				Resolutions: []int{75, 100, 150, 200, 300, 600},
				ScannableArea: ScannableArea{
					Height: 355.6,
					Width:  215.98466}},
		},
		{
			caps:            SourceCapabilities{},
			lorgnetteSource: LorgnetteSource{},
		},
	}

	for _, tc := range tests {
		got := tc.caps.ToLorgnetteSource()

		if !cmp.Equal(got, tc.lorgnetteSource) {
			t.Errorf("Expected %v, got %v for caps: %v", tc.lorgnetteSource, got, tc.caps)
		}
	}
}

// TestToLorgnetteCaps tests that the ToLorgnetteCaps function works correctly.
func TestToLorgnetteCaps(t *testing.T) {
	tests := []struct {
		caps          ScannerCapabilities
		lorgnetteCaps LorgnetteCapabilities
	}{
		{
			caps: ScannerCapabilities{
				PlatenInputCaps: SourceCapabilities{
					MaxWidth:  1200,
					MaxHeight: 2800,
					SettingProfile: SettingProfile{
						ColorModes: []string{"Grayscale16", "RGB24"},
						SupportedResolutions: SupportedResolutions{
							XResolutionRange: ResolutionRange{
								Min:    75,
								Max:    150,
								Normal: 150,
								Step:   75},
							YResolutionRange: ResolutionRange{
								Min:    75,
								Max:    150,
								Normal: 150,
								Step:   75}}}},
				AdfCapabilities: AdfCapabilities{
					AdfSimplexInputCaps: SourceCapabilities{
						MaxWidth:  2551,
						MaxHeight: 4200,
						SettingProfile: SettingProfile{
							ColorModes: []string{"BlackAndWhite1", "Grayscale8"},
							SupportedResolutions: SupportedResolutions{
								DiscreteResolutions: []DiscreteResolution{
									DiscreteResolution{
										XResolution: 100,
										YResolution: 200},
									DiscreteResolution{
										XResolution: 300,
										YResolution: 300}}}}},
					AdfDuplexInputCaps: SourceCapabilities{
						MaxWidth:  1850,
						MaxHeight: 3200,
						SettingProfile: SettingProfile{
							ColorModes: []string{"BlackAndWhite1", "RGB48"},
							SupportedResolutions: SupportedResolutions{
								DiscreteResolutions: []DiscreteResolution{
									DiscreteResolution{
										XResolution: 200,
										YResolution: 200},
									DiscreteResolution{
										XResolution: 600,
										YResolution: 600}}}}}}},
			lorgnetteCaps: LorgnetteCapabilities{
				PlatenCaps: LorgnetteSource{
					ColorModes:  []string{"MODE_UNSPECIFIED", "MODE_COLOR"},
					Resolutions: []int{75, 150},
					ScannableArea: ScannableArea{
						Height: 237.06667,
						Width:  101.6}},
				AdfSimplexCaps: LorgnetteSource{
					ColorModes:  []string{"MODE_GRAYSCALE"},
					Resolutions: []int{300},
					ScannableArea: ScannableArea{
						Height: 355.6,
						Width:  215.98466}},
				AdfDuplexCaps: LorgnetteSource{
					ColorModes:  []string{"MODE_UNSPECIFIED"},
					Resolutions: []int{200, 600},
					ScannableArea: ScannableArea{
						Height: 270.93333,
						Width:  156.63333}}},
		},
		{
			caps: ScannerCapabilities{
				PlatenInputCaps: SourceCapabilities{
					MaxWidth:  1200,
					MaxHeight: 2800,
					SettingProfile: SettingProfile{
						ColorModes: []string{"Grayscale16", "RGB24"},
						SupportedResolutions: SupportedResolutions{
							XResolutionRange: ResolutionRange{
								Min:    75,
								Max:    150,
								Normal: 150,
								Step:   75},
							YResolutionRange: ResolutionRange{
								Min:    75,
								Max:    150,
								Normal: 150,
								Step:   75}}}}},
			lorgnetteCaps: LorgnetteCapabilities{
				PlatenCaps: LorgnetteSource{
					ColorModes:  []string{"MODE_UNSPECIFIED", "MODE_COLOR"},
					Resolutions: []int{75, 150},
					ScannableArea: ScannableArea{
						Height: 237.06667,
						Width:  101.6}}},
		},
		{
			caps:          ScannerCapabilities{},
			lorgnetteCaps: LorgnetteCapabilities{},
		},
	}

	for _, tc := range tests {
		got := tc.caps.ToLorgnetteCaps()

		if !cmp.Equal(got, tc.lorgnetteCaps) {
			t.Errorf("Expected %v, got %v for caps: %v", tc.lorgnetteCaps, got, tc.caps)
		}
	}
}
