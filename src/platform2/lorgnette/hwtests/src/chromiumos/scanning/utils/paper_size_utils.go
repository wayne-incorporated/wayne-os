// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package utils

// inchesToMillimeters is the conversion factor from inches to mm.
const inchesToMillimeters = 25.4

// LetterSize represents letter-sized paper.
var LetterSize = PaperSize{heightInches: 11, widthInches: 8.5}

// PaperSize represents a particular size of paper.
type PaperSize struct {
	// Height of this paper size in inches.
	heightInches float32
	// Width of this paper size in inches.
	widthInches float32
}

// PixelWidthForResolution returns the number of pixels in width that an image
// of this paper size should be for the given resolution.
func (paperSize PaperSize) PixelWidthForResolution(resolution int) int {
	return int(paperSize.widthInches * float32(resolution))
}

// PixelHeightForResolution returns the number of pixels in height that an image
// of this paper size should be for the given resolution.
func (paperSize PaperSize) PixelHeightForResolution(resolution int) int {
	return int(paperSize.heightInches * float32(resolution))
}

// BottomRightX returns the lorgnette::ScanRegion bottom_right_x for this paper
// size. top_left_x is assumed to be 0.0.
func (paperSize PaperSize) BottomRightX() float32 {
	return paperSize.widthInches * inchesToMillimeters
}

// BottomRightY returns the lorgnette::ScanRegion bottom_right_y for this paper
// size. top_left_y is assumed to be 0.0.
func (paperSize PaperSize) BottomRightY() float32 {
	return paperSize.heightInches * inchesToMillimeters
}
