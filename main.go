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
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	raw := flag.Bool("raw", false, "treat each input line as a password itself, instead of scanning for key=value assignments")
	flag.Parse()

	args := flag.Args()
	exitCode := 0

	if len(args) == 0 {
		if !scanSource("stdin", os.Stdin, *raw) {
			exitCode = 1
		}
	} else {
		for _, path := range args {
			if path == "-" {
				if !scanSource("stdin", os.Stdin, *raw) {
					exitCode = 1
				}
				continue
			}

			f, err := os.Open(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "passlint: %v\n", err)
				exitCode = 2
				continue
			}
			clean := scanSource(path, f, *raw)
			f.Close()
			if !clean {
				exitCode = 1
			}
		}
	}

	os.Exit(exitCode)
}

// scanSource reads r line by line, printing one line of output per finding.
// It returns false if it reported anything, so the caller can turn that
// into a non-zero exit status without keeping its own counters.
func scanSource(name string, r io.Reader, raw bool) bool {
	clean := true
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
				clean = false
				fmt.Printf("%s:%d: %s: %s\n", name, lineNo, f.Severity, f.Message)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "passlint: %s: %v\n", name, err)
	}

	return clean
}
