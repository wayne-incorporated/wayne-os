// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package utils

import (
	"testing"
)

// TestPixelWidthForResolution tests that PixelWidthForResolution returns the
// correct values for standard paper sizes.
func TestPixelWidthForResolution(t *testing.T) {
	tests := []struct {
		paperSize  PaperSize
		resolution int
		width      int
	}{
		{
			paperSize:  LetterSize,
			resolution: 75,
			width:      637,
		},
		{
			paperSize:  LetterSize,
			resolution: 150,
			width:      1275,
		},
		{
			paperSize:  LetterSize,
			resolution: 200,
			width:      1700,
		},
		{
			paperSize:  LetterSize,
			resolution: 300,
			width:      2550,
		},
		{
			paperSize:  LetterSize,
			resolution: 600,
			width:      5100,
		},
		{
			paperSize:  LetterSize,
			resolution: 1200,
			width:      10200,
		},
	}

	for _, tc := range tests {
		width := tc.paperSize.PixelWidthForResolution(tc.resolution)

		if width != tc.width {
			t.Errorf("Width: got %d, want %d for paper size: %v and resolution: %d", width, tc.width, tc.paperSize, tc.resolution)
		}
	}
}

// TestPixelHeightForResolution tests that PixelHeightForResolution returns the
// correct values for standard paper sizes.
func TestPixelHeightForResolution(t *testing.T) {
	tests := []struct {
		paperSize  PaperSize
		resolution int
		height     int
	}{
		{
			paperSize:  LetterSize,
			resolution: 75,
			height:     825,
		},
		{
			paperSize:  LetterSize,
			resolution: 150,
			height:     1650,
		},
		{
			paperSize:  LetterSize,
			resolution: 200,
			height:     2200,
		},
		{
			paperSize:  LetterSize,
			resolution: 300,
			height:     3300,
		},
		{
			paperSize:  LetterSize,
			resolution: 600,
			height:     6600,
		},
		{
			paperSize:  LetterSize,
			resolution: 1200,
			height:     13200,
		},
	}

	for _, tc := range tests {
		height := tc.paperSize.PixelHeightForResolution(tc.resolution)

		if height != tc.height {
			t.Errorf("Height: got %d, want %d for paper size: %v and resolution: %d", height, tc.height, tc.paperSize, tc.resolution)
		}
	}
}

// TestBottomRightX tests that BottomRightX returns the correct values for
// standard paper sizes.
func TestBottomRightX(t *testing.T) {
	tests := []struct {
		paperSize    PaperSize
		bottomRightX float32
	}{
		{
			paperSize:    LetterSize,
			bottomRightX: 215.9,
		},
	}

	for _, tc := range tests {
		got := tc.paperSize.BottomRightX()

		if got != tc.bottomRightX {
			t.Errorf("BottomRightX: got %f, want %f for paper size: %v", got, tc.bottomRightX, tc.paperSize)
		}
	}
}

// TestBottomRightYtests that BottomRightY returns the correct values for
// standard paper sizes.
func TestBottomRightY(t *testing.T) {
	tests := []struct {
		paperSize    PaperSize
		bottomRightY float32
	}{
		{
			paperSize:    LetterSize,
			bottomRightY: 279.4,
		},
	}

	for _, tc := range tests {
		got := tc.paperSize.BottomRightY()

		if got != tc.bottomRightY {
			t.Errorf("BottomRightY: got %f, want %f for paper size: %v", got, tc.bottomRightY, tc.paperSize)
		}
	}
}
