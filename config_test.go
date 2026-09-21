package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passlint.json")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("writing test config: %v", err)
	}
	return path
}

func TestLoadConfigEmptyPathReturnsDefaults(t *testing.T) {
	cfg, err := loadConfig("")
	if err != nil {
		t.Fatalf("loadConfig(\"\") returned error: %v", err)
	}
	want := defaultConfig()
	if cfg.MinLength != want.MinLength || cfg.RecommendedLength != want.RecommendedLength ||
		len(cfg.ExtraPasswords) != 0 || len(cfg.DisabledChecks) != 0 {
		t.Errorf("loadConfig(\"\") = %+v, want %+v", cfg, want)
	}
}

func TestLoadConfigPartialOverrideKeepsOtherDefaults(t *testing.T) {
	path := writeConfig(t, `{"extra_passwords": ["hunter2"]}`)

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig(%q) returned error: %v", path, err)
	}
	if cfg.MinLength != defaultConfig().MinLength {
		t.Errorf("loadConfig with only extra_passwords set MinLength = %d, want default %d", cfg.MinLength, defaultConfig().MinLength)
	}
	if len(cfg.ExtraPasswords) != 1 || cfg.ExtraPasswords[0] != "hunter2" {
		t.Errorf("loadConfig ExtraPasswords = %v, want [hunter2]", cfg.ExtraPasswords)
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	if _, err := loadConfig(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("loadConfig on a missing file returned no error")
	}
}

func TestLoadConfigInvalidJSON(t *testing.T) {
	path := writeConfig(t, `{not valid json`)
	if _, err := loadConfig(path); err == nil {
		t.Error("loadConfig on invalid JSON returned no error")
	}
}

func TestLoadConfigUnknownField(t *testing.T) {
	path := writeConfig(t, `{"minlength": 10}`)
	if _, err := loadConfig(path); err == nil {
		t.Error("loadConfig with an unknown field returned no error")
	}
}

func TestLoadConfigValidatesThresholds(t *testing.T) {
	cases := []string{
		`{"min_length": 0}`,
		`{"min_length": -1}`,
		`{"min_length": 10, "recommended_length": 8}`,
	}
	for _, c := range cases {
		path := writeConfig(t, c)
		if _, err := loadConfig(path); err == nil {
			t.Errorf("loadConfig(%s) returned no error, want a validation error", c)
		}
	}
}

func TestLoadConfigValidatesDisabledChecks(t *testing.T) {
	path := writeConfig(t, `{"disabled_checks": ["not_a_real_check"]}`)
	if _, err := loadConfig(path); err == nil {
		t.Error("loadConfig with an unknown disabled check returned no error")
	}
}

func TestConfigThresholdsChangeFindings(t *testing.T) {
	path := writeConfig(t, `{"min_length": 4, "recommended_length": 6}`)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig(%q) returned error: %v", path, err)
	}

	findings := checkPassword("Zq9!", cfg)
	if hasFindingContaining(findings, "minimum is") {
		t.Errorf("checkPassword with a lowered min_length still reported a minimum-length error: %v", findingMessages(findings))
	}
}

func TestConfigExtraPasswords(t *testing.T) {
	path := writeConfig(t, `{"extra_passwords": ["CorrectHorseBattery1!"]}`)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig(%q) returned error: %v", path, err)
	}

	findings := checkPassword("CorrectHorseBattery1!", cfg)
	if !hasFindingContaining(findings, "commonly used password") {
		t.Errorf("checkPassword(%q) with extra_passwords = %v, want a common password finding", "CorrectHorseBattery1!", findingMessages(findings))
	}

	// Case-insensitive, like the built-in list.
	findings = checkPassword("correcthorsebattery1!", cfg)
	if !hasFindingContaining(findings, "commonly used password") {
		t.Errorf("checkPassword on a differently-cased extra password reported no finding: %v", findingMessages(findings))
	}
}

func TestConfigDisabledChecks(t *testing.T) {
	path := writeConfig(t, `{"disabled_checks": ["common"]}`)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig(%q) returned error: %v", path, err)
	}

	findings := checkPassword("password", cfg)
	if hasFindingContaining(findings, "commonly used password") {
		t.Errorf("checkPassword(%q) with the common check disabled = %v, want no common password finding", "password", findingMessages(findings))
	}
}

func TestLoadConfigErrorMentionsPath(t *testing.T) {
	path := writeConfig(t, `{"min_length": 0}`)
	_, err := loadConfig(path)
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Errorf("loadConfig(%q) error = %v, want it to mention the path", path, err)
	}
}
