package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Config holds the thresholds and rule toggles checkPassword uses. The zero
// value is not valid on its own; use defaultConfig or loadConfig, both of
// which fill in the built-in defaults before any overrides are applied.
type Config struct {
	MinLength         int      `json:"min_length"`
	RecommendedLength int      `json:"recommended_length"`
	ExtraPasswords    []string `json:"extra_passwords"`
	DisabledChecks    []string `json:"disabled_checks"`
}

// checkNames are the rules checkPassword can run, and the only values valid
// in a config file's disabled_checks list.
var checkNames = map[string]bool{
	"length":       true,
	"common":       true,
	"char_classes": true,
	"repeated_run": true,
	"keyboard_run": true,
}

// defaultConfig matches the thresholds passlint used before -config existed,
// so running without the flag behaves exactly as it always has.
func defaultConfig() Config {
	return Config{
		MinLength:         8,
		RecommendedLength: 12,
	}
}

// loadConfig reads a JSON config file at path and validates it. An empty
// path returns the defaults untouched, which is what -config's zero value
// means: no file given.
func loadConfig(path string) (Config, error) {
	cfg := defaultConfig()
	if path == "" {
		return cfg, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()

	// Decoding into cfg (already carrying the defaults) means a config file
	// that only sets one field, say extra_passwords, leaves the rest at
	// their built-in values instead of zeroing them out.
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parsing %s: %w", path, err)
	}

	if cfg.MinLength <= 0 {
		return Config{}, fmt.Errorf("%s: min_length must be positive", path)
	}
	if cfg.RecommendedLength < cfg.MinLength {
		return Config{}, fmt.Errorf("%s: recommended_length must be >= min_length", path)
	}
	for _, name := range cfg.DisabledChecks {
		if !checkNames[name] {
			return Config{}, fmt.Errorf("%s: unknown check %q in disabled_checks", path, name)
		}
	}

	return cfg, nil
}

// enabled reports whether the named check should run.
func (c Config) enabled(name string) bool {
	for _, d := range c.DisabledChecks {
		if d == name {
			return false
		}
	}
	return true
}

// isExtraPassword reports whether pw matches one of the config's own
// blocklist entries, checked case-insensitively like the built-in list.
func (c Config) isExtraPassword(pw string) bool {
	for _, p := range c.ExtraPasswords {
		if strings.EqualFold(p, pw) {
			return true
		}
	}
	return false
}
