package main

import (
	"strings"
	"testing"
)

func findingMessages(findings []Finding) []string {
	msgs := make([]string, len(findings))
	for i, f := range findings {
		msgs[i] = f.Message
	}
	return msgs
}

func hasFindingContaining(findings []Finding, substr string) bool {
	for _, f := range findings {
		if strings.Contains(f.Message, substr) {
			return true
		}
	}
	return false
}

func TestCheckPasswordLength(t *testing.T) {
	cases := []struct {
		name     string
		pw       string
		severity string
		want     bool // whether a length finding is expected
	}{
		{"too short", "ab1", "error", true},
		{"under recommended", "abcdefgH1", "warning", true},
		{"long enough", "abcdefghijK1!", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := checkPassword(tc.pw)
			var got *Finding
			for i := range findings {
				if strings.Contains(findings[i].Message, "characters") {
					got = &findings[i]
					break
				}
			}
			if tc.want && got == nil {
				t.Fatalf("checkPassword(%q) = %v, want a length finding", tc.pw, findingMessages(findings))
			}
			if !tc.want && got != nil {
				t.Fatalf("checkPassword(%q) unexpectedly reported a length finding: %s", tc.pw, got.Message)
			}
			if tc.want && got.Severity != tc.severity {
				t.Errorf("checkPassword(%q) length finding severity = %q, want %q", tc.pw, got.Severity, tc.severity)
			}
		})
	}
}

func TestCheckPasswordCommonList(t *testing.T) {
	for _, pw := range []string{"password", "PASSWORD", "PaSsWoRd", "qwerty123", "trustno1", "P@ssword"} {
		findings := checkPassword(pw)
		if !hasFindingContaining(findings, "commonly used password") {
			t.Errorf("checkPassword(%q) = %v, want a common password finding", pw, findingMessages(findings))
		}
	}

	findings := checkPassword("Xk8#mQ2p!Zv9")
	if hasFindingContaining(findings, "commonly used password") {
		t.Errorf("checkPassword on a non-common password reported a common password finding: %v", findingMessages(findings))
	}
}

func TestCommonPasswordsLowercase(t *testing.T) {
	// checkPassword only ever looks up strings.ToLower(pw), so an entry with
	// any uppercase in it would silently never match.
	for pw := range commonPasswords {
		if pw != strings.ToLower(pw) {
			t.Errorf("commonPasswords contains %q, which is not lowercase and will never match", pw)
		}
	}
}

func TestCheckPasswordMissingCharClasses(t *testing.T) {
	// Only lowercase and digits present, so two classes (upper, symbol) are
	// missing and the finding should fire.
	findings := checkPassword("abcdefgh123")
	if !hasFindingContaining(findings, "missing") {
		t.Errorf("checkPassword(%q) = %v, want a missing-char-class finding", "abcdefgh123", findingMessages(findings))
	}

	// Only one class missing (symbols) should not trigger the finding.
	findings = checkPassword("abcdEFGH123")
	if hasFindingContaining(findings, "missing") {
		t.Errorf("checkPassword(%q) unexpectedly reported a missing-char-class finding: %v", "abcdEFGH123", findingMessages(findings))
	}
}

func TestCheckPasswordRepeatedRun(t *testing.T) {
	findings := checkPassword("aaaaBcd123!")
	if !hasFindingContaining(findings, "repeated") {
		t.Errorf("checkPassword with a repeated run = %v, want a repeated-run finding", findingMessages(findings))
	}

	findings = checkPassword("aaaBcd123!Z")
	if hasFindingContaining(findings, "repeated") {
		t.Errorf("checkPassword with only 3 repeats unexpectedly reported a repeated-run finding: %v", findingMessages(findings))
	}
}

func TestCheckPasswordKeyboardRun(t *testing.T) {
	findings := checkPassword("myqwertyPass1!")
	if !hasFindingContaining(findings, "keyboard or numeric sequence") {
		t.Errorf("checkPassword with a keyboard run = %v, want a keyboard-run finding", findingMessages(findings))
	}
}

func TestMissingCharClasses(t *testing.T) {
	cases := []struct {
		pw   string
		want []string
	}{
		{"abc123", []string{"uppercase letters", "symbols"}},
		{"ABC123", []string{"lowercase letters", "symbols"}},
		{"Abc!def", []string{"digits"}},
		{"Abc123!", nil},
	}

	for _, tc := range cases {
		got := missingCharClasses(tc.pw)
		if len(got) != len(tc.want) {
			t.Errorf("missingCharClasses(%q) = %v, want %v", tc.pw, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("missingCharClasses(%q) = %v, want %v", tc.pw, got, tc.want)
				break
			}
		}
	}
}

func TestHasRepeatedRun(t *testing.T) {
	cases := []struct {
		pw   string
		n    int
		want bool
	}{
		{"aaaa", 4, true},
		{"aaa", 4, false},
		{"abcaaaa", 4, true},
		{"abcabc", 4, false},
		{"", 4, false},
	}

	for _, tc := range cases {
		if got := hasRepeatedRun(tc.pw, tc.n); got != tc.want {
			t.Errorf("hasRepeatedRun(%q, %d) = %v, want %v", tc.pw, tc.n, got, tc.want)
		}
	}
}

func TestContainsKeyboardRun(t *testing.T) {
	cases := []struct {
		pw   string
		want bool
	}{
		{"qwerty", true},
		{"QWERTY", true},
		{"ytrewq", true}, // reversed run
		{"1234", true},
		{"asdf", true},
		{"randomXY9", false},
	}

	for _, tc := range cases {
		if got := containsKeyboardRun(tc.pw); got != tc.want {
			t.Errorf("containsKeyboardRun(%q) = %v, want %v", tc.pw, got, tc.want)
		}
	}
}

func TestRedact(t *testing.T) {
	cases := []struct {
		pw   string
		want string
	}{
		{"", ""},
		{"ab", "**"},
		{"abcd", "****"},
		{"abcdef", "ab**ef"},
		{"password1", "pa*****d1"},
	}

	for _, tc := range cases {
		if got := redact(tc.pw); got != tc.want {
			t.Errorf("redact(%q) = %q, want %q", tc.pw, got, tc.want)
		}
	}
}

func TestExtractCandidates(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{`password = "hunter22"`, []string{"hunter22"}},
		{`pwd: letmein99`, []string{"letmein99"}},
		{`Secret="topsecret1"`, []string{"topsecret1"}},
		{`TOKEN = abc.def.ghi`, []string{"abc.def.ghi"}},
		{`user = "alice"`, nil},
		{`# just a comment`, nil},
		{`password="first1" token="second2"`, []string{"first1", "second2"}},
	}

	for _, tc := range cases {
		got := extractCandidates(tc.line)
		if len(got) != len(tc.want) {
			t.Errorf("extractCandidates(%q) = %v, want %v", tc.line, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("extractCandidates(%q) = %v, want %v", tc.line, got, tc.want)
				break
			}
		}
	}
}
