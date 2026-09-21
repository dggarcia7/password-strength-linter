// Command passlint scans files (or stdin) for weak passwords and reports
// findings as "path:line: severity: message", in the style of a linter.
//
// By default it looks for key = value / key: value assignments where the
// key looks like a password field (password, pwd, secret, token, ...) and
// checks the value. With -raw it treats every non-empty line as a password
// on its own, which is the right mode for auditing a plain wordlist.
//
// A line containing "passlint:ignore" is skipped entirely, so a known and
// accepted value (a test fixture, say) can be excluded without disabling
// the rule everywhere.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// ignoreMarker suppresses findings on the line it appears on, the same way
// linters let you silence a rule inline instead of restructuring the code.
const ignoreMarker = "passlint:ignore"

// report is one finding formatted for output, either as a text line or as
// an element of the -json array.
type report struct {
	Path     string `json:"path"`
	Line     int    `json:"line"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

func main() {
	raw := flag.Bool("raw", false, "treat each input line as a password itself, instead of scanning for key=value assignments")
	jsonOutput := flag.Bool("json", false, "report findings as a JSON array instead of text lines")
	failOn := flag.String("fail-on", "warning", "minimum severity that causes a non-zero exit code: error, warning, or none")
	configPath := flag.String("config", "", "path to a JSON config file overriding thresholds and enabled checks (see README)")
	flag.Parse()

	switch *failOn {
	case "error", "warning", "none":
	default:
		fmt.Fprintf(os.Stderr, "passlint: invalid -fail-on value %q, want error, warning, or none\n", *failOn)
		os.Exit(2)
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "passlint: %v\n", err)
		os.Exit(2)
	}

	args := flag.Args()
	hadOpenErr := false
	reports := make([]report, 0)

	scan := func(name string, r io.Reader) {
		found, err := scanSource(name, r, *raw, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "passlint: %s: %v\n", name, err)
		}
		reports = append(reports, found...)
	}

	if len(args) == 0 {
		scan("stdin", os.Stdin)
	} else {
		for _, path := range args {
			if path == "-" {
				scan("stdin", os.Stdin)
				continue
			}

			f, err := os.Open(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "passlint: %v\n", err)
				hadOpenErr = true
				continue
			}
			scan(path, f)
			f.Close()
		}
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(reports); err != nil {
			fmt.Fprintf(os.Stderr, "passlint: %v\n", err)
			os.Exit(2)
		}
	} else {
		for _, r := range reports {
			fmt.Printf("%s:%d: %s: %s\n", r.Path, r.Line, r.Severity, r.Message)
		}
	}

	switch {
	case hadOpenErr:
		os.Exit(2)
	case meetsFailThreshold(reports, *failOn):
		os.Exit(1)
	default:
		os.Exit(0)
	}
}

// meetsFailThreshold reports whether reports contains a finding severe
// enough to warrant a non-zero exit code under failOn, which is one of
// "error", "warning", or "none" (already validated by the caller).
func meetsFailThreshold(reports []report, failOn string) bool {
	switch failOn {
	case "none":
		return false
	case "error":
		for _, r := range reports {
			if r.Severity == "error" {
				return true
			}
		}
		return false
	default: // "warning"
		return len(reports) > 0
	}
}

// scanSource reads r line by line and returns one report per finding.
func scanSource(name string, r io.Reader, raw bool, cfg Config) ([]report, error) {
	var found []report
	scanner := bufio.NewScanner(r)
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := scanner.Text()

		if strings.Contains(line, ignoreMarker) {
			continue
		}

		var candidates []string
		if raw {
			if line != "" {
				candidates = []string{line}
			}
		} else {
			candidates = extractCandidates(line)
		}

		for _, pw := range candidates {
			for _, f := range checkPassword(pw, cfg) {
				found = append(found, report{
					Path:     name,
					Line:     lineNo,
					Severity: f.Severity,
					Message:  f.Message,
				})
			}
		}
	}

	return found, scanner.Err()
}
