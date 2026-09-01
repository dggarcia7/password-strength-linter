package main

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// Finding is one thing wrong with a candidate password.
type Finding struct {
	Severity string // "error" or "warning"
	Message  string
}

// assignmentPattern matches "key = value" or "key: value" style lines where
// key looks like a password field. The value may be quoted or bare.
var assignmentPattern = regexp.MustCompile(`(?i)(pass(word)?|pwd|secret|token)\s*[:=]\s*['"]?([^'"\s]+)['"]?`)

func extractCandidates(line string) []string {
	matches := assignmentPattern.FindAllStringSubmatch(line, -1)
	if matches == nil {
		return nil
	}
	candidates := make([]string, 0, len(matches))
	for _, m := range matches {
		candidates = append(candidates, m[3])
	}
	return candidates
}

// commonPasswords is a small seed list of the most frequently reused
// passwords. It's deliberately short for now; see the roadmap in README.md.
var commonPasswords = map[string]bool{
	"password":  true,
	"123456":    true,
	"12345678":  true,
	"123456789": true,
	"qwerty":    true,
	"letmein":   true,
	"admin":     true,
	"welcome":   true,
	"monkey":    true,
	"dragon":    true,
	"iloveyou":  true,
	"abc123":    true,
	"111111":    true,
	"password1": true,
}

// keyboardRuns are substrings that show up whenever someone types along a
// keyboard row or a simple counting sequence instead of picking characters
// independently.
var keyboardRuns = []string{
	"0123456789",
	"abcdefghijklmnopqrstuvwxyz",
	"qwertyuiop",
	"asdfghjkl",
	"zxcvbnm",
}

func checkPassword(pw string) []Finding {
	var findings []Finding

	switch n := len(pw); {
	case n < 8:
		findings = append(findings, Finding{"error",
			fmt.Sprintf("only %d characters, minimum is 8 (%s)", n, redact(pw))})
	case n < 12:
		findings = append(findings, Finding{"warning",
			fmt.Sprintf("only %d characters, 12 or more is recommended (%s)", n, redact(pw))})
	}

	if commonPasswords[strings.ToLower(pw)] {
		findings = append(findings, Finding{"error",
			fmt.Sprintf("matches a commonly used password (%s)", redact(pw))})
	}

	if missing := missingCharClasses(pw); len(missing) >= 2 {
		findings = append(findings, Finding{"warning",
			fmt.Sprintf("missing %s (%s)", strings.Join(missing, ", "), redact(pw))})
	}

	if hasRepeatedRun(pw, 4) {
		findings = append(findings, Finding{"warning",
			fmt.Sprintf("contains a character repeated 4 or more times in a row (%s)", redact(pw))})
	}

	if containsKeyboardRun(pw) {
		findings = append(findings, Finding{"warning",
			fmt.Sprintf("contains a common keyboard or numeric sequence (%s)", redact(pw))})
	}

	return findings
}

func missingCharClasses(pw string) []string {
	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, r := range pw {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasSymbol = true
		}
	}

	var missing []string
	if !hasUpper {
		missing = append(missing, "uppercase letters")
	}
	if !hasLower {
		missing = append(missing, "lowercase letters")
	}
	if !hasDigit {
		missing = append(missing, "digits")
	}
	if !hasSymbol {
		missing = append(missing, "symbols")
	}
	return missing
}

func hasRepeatedRun(pw string, n int) bool {
	runes := []rune(pw)
	run := 1
	for i := 1; i < len(runes); i++ {
		if runes[i] == runes[i-1] {
			run++
			if run >= n {
				return true
			}
		} else {
			run = 1
		}
	}
	return false
}

func containsKeyboardRun(pw string) bool {
	const runLen = 4
	lower := strings.ToLower(pw)

	for _, seq := range keyboardRuns {
		for i := 0; i+runLen <= len(seq); i++ {
			fwd := seq[i : i+runLen]
			if strings.Contains(lower, fwd) || strings.Contains(lower, reverse(fwd)) {
				return true
			}
		}
	}
	return false
}

func reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// redact keeps a couple of characters at each end so findings are still
// recognizable in a terminal without printing the whole password.
func redact(pw string) string {
	if len(pw) <= 4 {
		return strings.Repeat("*", len(pw))
	}
	return pw[:2] + strings.Repeat("*", len(pw)-4) + pw[len(pw)-2:]
}
