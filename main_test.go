package main

import (
	"strings"
	"testing"
)

func TestScanSourceIgnoreMarker(t *testing.T) {
	input := "password = \"hunter22\" # passlint:ignore\ntoken: qwerty123\n"

	found, err := scanSource("test", strings.NewReader(input), false, defaultConfig())
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

	found, err := scanSource("test", strings.NewReader(input), true, defaultConfig())
	if err != nil {
		t.Fatalf("scanSource returned error: %v", err)
	}

	for _, r := range found {
		if r.Line == 2 {
			t.Errorf("scanSource reported a finding on an ignored line: %+v", r)
		}
	}
}

func TestMeetsFailThreshold(t *testing.T) {
	reports := []report{
		{Path: "test", Line: 1, Severity: "warning", Message: "too short"},
	}

	cases := []struct {
		failOn string
		want   bool
	}{
		{"warning", true},
		{"error", false},
		{"none", false},
	}
	for _, c := range cases {
		if got := meetsFailThreshold(reports, c.failOn); got != c.want {
			t.Errorf("meetsFailThreshold(warning-only, %q) = %v, want %v", c.failOn, got, c.want)
		}
	}

	reports = append(reports, report{Path: "test", Line: 2, Severity: "error", Message: "common password"})
	if !meetsFailThreshold(reports, "error") {
		t.Errorf("meetsFailThreshold(with error, %q) = false, want true", "error")
	}

	if meetsFailThreshold(nil, "warning") {
		t.Errorf("meetsFailThreshold(nil, %q) = true, want false", "warning")
	}
}
