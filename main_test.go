package main

import (
	"strings"
	"testing"
)

func TestScanSourceIgnoreMarker(t *testing.T) {
	input := "password = \"hunter22\" # passlint:ignore\ntoken: qwerty123\n"

	found, err := scanSource("test", strings.NewReader(input), false)
	if err != nil {
		t.Fatalf("scanSource returned error: %v", err)
	}

	for _, r := range found {
		if r.Line == 1 {
			t.Errorf("scanSource reported a finding on an ignored line: %+v", r)
		}
	}

	sawLine2 := false
	for _, r := range found {
		if r.Line == 2 {
			sawLine2 = true
		}
	}
	if !sawLine2 {
		t.Errorf("scanSource(%q) = %v, want at least one finding on line 2", input, found)
	}
}

func TestScanSourceIgnoreMarkerRaw(t *testing.T) {
	input := "password1\nqwerty # passlint:ignore\n"

	found, err := scanSource("test", strings.NewReader(input), true)
	if err != nil {
		t.Fatalf("scanSource returned error: %v", err)
	}

	for _, r := range found {
		if r.Line == 2 {
			t.Errorf("scanSource reported a finding on an ignored line: %+v", r)
		}
	}
}
