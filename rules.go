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

// commonPasswords collects passwords that show up over and over in public
// breach dumps and "worst passwords of the year" roundups: keyboard walks,
// digit runs, sports teams, first names, and the obvious password/password1
// variants. Checked case-insensitively, so casing tricks don't help.
var commonPasswords = map[string]bool{
	// digit runs and keyboard walks
	"123456": true, "12345678": true, "123456789": true, "1234567890": true,
	"1234567": true, "12345": true, "1234": true, "123123": true,
	"123321": true, "000000": true, "111111": true, "121212": true,
	"222222": true, "333333": true, "555555": true, "666666": true,
	"696969": true, "777777": true, "999999": true,
	"qwerty": true, "qwerty1": true, "qwerty123": true, "qwertyuiop": true,
	"asdfgh": true, "asdfghjkl": true, "zxcvbnm": true, "zaq1zaq1": true,
	"1q2w3e": true, "1q2w3e4r": true, "1qaz2wsx": true, "qazwsx": true,

	// password/admin/default variants
	"password": true, "password1": true, "password123": true, "password2": true,
	"passw0rd": true, "p@ssword": true, "letmein": true, "letmein1": true,
	"admin": true, "root": true, "toor": true, "guest": true,
	"test": true, "test123": true, "changeme": true, "temp123": true,
	"default": true, "welcome": true, "trustno1": true, "opensesame": true,
	"secret": true, "access": true, "master": true, "shadow": true,

	// dictionary words, names, and topical picks
	"abc123": true, "iloveyou": true, "monkey": true, "monkey1": true,
	"dragon": true, "princess": true, "sunshine": true, "ashley": true,
	"bailey": true, "hunter": true, "ranger": true, "buster": true,
	"thomas": true, "robert": true, "michael": true, "jennifer": true,
	"jordan": true, "andrew": true, "charlie": true, "jessica": true,
	"michelle": true, "amanda": true, "hannah": true, "joshua": true,
	"matthew": true, "maggie": true, "tigger": true, "snoopy": true,
	"ginger": true, "purple": true, "orange": true, "banana": true,
	"diamond": true, "nascar": true, "jasmine": true, "dakota": true,
	"cameron": true, "george": true, "sexy": true, "killer": true,
	"love": true, "love123": true, "jesus": true, "angel": true, "angel1": true,
	"whatever": true, "freedom": true, "computer": true, "internet": true,
	"coffee": true, "chocolate": true, "cookie": true, "summer": true,
	"winter": true, "flower": true,

	// sports and pop culture
	"football": true, "baseball": true, "basketball": true, "soccer": true,
	"hockey": true, "yankees": true, "chelsea": true, "arsenal": true,
	"liverpool": true, "barcelona": true, "mustang": true, "harley": true,
	"corvette": true, "dallas": true, "biteme": true, "panties": true,
	"pepper": true, "batman": true, "superman": true, "spiderman": true,
	"ironman": true, "ninja": true, "samurai": true, "starwars": true,
	"pokemon": true,
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

func checkPassword(pw string, cfg Config) []Finding {
	var findings []Finding

	if cfg.enabled("length") {
		switch n := len(pw); {
		case n < cfg.MinLength:
			findings = append(findings, Finding{"error",
				fmt.Sprintf("only %d characters, minimum is %d (%s)", n, cfg.MinLength, redact(pw))})
		case n < cfg.RecommendedLength:
			findings = append(findings, Finding{"warning",
				fmt.Sprintf("only %d characters, %d or more is recommended (%s)", n, cfg.RecommendedLength, redact(pw))})
		}
	}

	if cfg.enabled("common") {
		if commonPasswords[strings.ToLower(pw)] || cfg.isExtraPassword(pw) {
			findings = append(findings, Finding{"error",
				fmt.Sprintf("matches a commonly used password (%s)", redact(pw))})
		}
	}

	if cfg.enabled("char_classes") {
		if missing := missingCharClasses(pw); len(missing) >= 2 {
			findings = append(findings, Finding{"warning",
				fmt.Sprintf("missing %s (%s)", strings.Join(missing, ", "), redact(pw))})
		}
	}

	if cfg.enabled("repeated_run") {
		if hasRepeatedRun(pw, 4) {
			findings = append(findings, Finding{"warning",
				fmt.Sprintf("contains a character repeated 4 or more times in a row (%s)", redact(pw))})
		}
	}

	if cfg.enabled("keyboard_run") {
		if containsKeyboardRun(pw) {
			findings = append(findings, Finding{"warning",
				fmt.Sprintf("contains a common keyboard or numeric sequence (%s)", redact(pw))})
		}
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
