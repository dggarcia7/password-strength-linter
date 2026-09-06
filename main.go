// Command passlint scans files (or stdin) for weak passwords and reports
// findings as "path:line: severity: message", in the style of a linter.
//
// By default it looks for key = value / key: value assignments where the
// key looks like a password field (password, pwd, secret, token, ...) and
// checks the value. With -raw it treats every non-empty line as a password
// on its own, which is the right mode for auditing a plain wordlist.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
)

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
	flag.Parse()

	args := flag.Args()
	exitCode := 0
	reports := make([]report, 0)

	scan := func(name string, r io.Reader) {
		found, err := scanSource(name, r, *raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "passlint: %s: %v\n", name, err)
		}
		if len(found) > 0 {
			exitCode = 1
			reports = append(reports, found...)
		}
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
				exitCode = 2
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
			exitCode = 2
		}
	} else {
		for _, r := range reports {
			fmt.Printf("%s:%d: %s: %s\n", r.Path, r.Line, r.Severity, r.Message)
		}
	}

	os.Exit(exitCode)
}

// scanSource reads r line by line and returns one report per finding.
func scanSource(name string, r io.Reader, raw bool) ([]report, error) {
	var found []report
	scanner := bufio.NewScanner(r)
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := scanner.Text()

		var candidates []string
		if raw {
			if line != "" {
				candidates = []string{line}
			}
		} else {
			candidates = extractCandidates(line)
		}

		for _, pw := range candidates {
			for _, f := range checkPassword(pw) {
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
