# passlint

A linter for passwords. It scans files or stdin, line by line, and reports
weak passwords the way a code linter reports style problems: one line per
finding, with the file name and line number attached.

There are two things it's useful for:

- Catching a hardcoded password in a config file or `.env` before it gets
  committed (`db.password = "qwerty"` in a Helm values file, for example).
- Auditing a plain wordlist of passwords, one per line, for the obviously
  weak ones.

## Build

```
go build -o passlint .
```

No third-party dependencies, so a plain `go build` is all it takes.

## Usage

By default passlint looks for `key = value` or `key: value` lines where the
key looks like a password field (`password`, `pwd`, `secret`, `token`, ...)
and checks the value on the right:

```
$ cat config.yaml
database:
  host: db.internal
  user: app
  password: "abc123"

$ passlint config.yaml
config.yaml:4: error: only 6 characters, minimum is 8 (ab***23)
config.yaml:4: error: matches a commonly used password (ab***23)
config.yaml:4: warning: missing uppercase letters, symbols (ab***23)
```

It reads from stdin when no files are given, or when a file argument is `-`,
so it fits into a pipeline:

```
$ git show HEAD:.env | passlint
$ cat .env | passlint -
```

For a plain wordlist (one password per line, no keys), pass `-raw` so every
line is checked directly instead of being matched against the key=value
pattern:

```
$ passlint -raw passwords.txt
passwords.txt:1: error: matches a commonly used password (pa***rd)
passwords.txt:9: warning: only 10 characters, 12 or more is recommended (su***23)
```

A line containing `passlint:ignore` is skipped entirely, for a known and
accepted value such as a test fixture:

```
$ cat fixtures.env
password = "hunter22" # passlint:ignore
token: qwerty123
$ passlint fixtures.env
fixtures.env:2: warning: only 9 characters, 12 or more is recommended (qw*****23)
fixtures.env:2: error: matches a commonly used password (qw*****23)
fixtures.env:2: warning: missing uppercase letters, symbols (qw*****23)
fixtures.env:2: warning: contains a common keyboard or numeric sequence (qw*****23)
```

passlint exits `1` if it reported any findings, `2` if a file couldn't be
opened, and `0` if the input was clean, so it can be used as a CI gate.

Pass `-fail-on` to control which severities count toward that exit code.
`-fail-on error` exits `0` on warnings and only fails the build on errors,
which is useful during a migration when you want visibility into warnings
without blocking on them yet. `-fail-on none` always exits `0` (unless a
file couldn't be opened), for a report-only mode. The default is
`-fail-on warning`, matching the behavior above.

```
$ passlint -fail-on error fixtures.env; echo "exit: $?"
fixtures.env:2: warning: only 9 characters, 12 or more is recommended (qw*****23)
fixtures.env:2: error: matches a commonly used password (qw*****23)
fixtures.env:2: warning: missing uppercase letters, symbols (qw*****23)
fixtures.env:2: warning: contains a common keyboard or numeric sequence (qw*****23)
exit: 1
```

Passwords in findings are redacted to the first and last two characters so
the actual value doesn't end up sitting in build logs.

Pass `-json` to get findings as a JSON array instead of text lines, which is
easier for a CI pipeline to parse than scraping stdout:

```
$ passlint -json config.yaml
[
  {
    "path": "config.yaml",
    "line": 4,
    "severity": "error",
    "message": "only 6 characters, minimum is 8 (ab***23)"
  }
]
```

The array is printed once, after all files have been scanned, and is empty
(`[]`) when nothing was found.

## Config file

The built-in thresholds and checks won't fit every project. Pass `-config`
with a path to a JSON file to override them:

```
$ cat passlint.json
{
  "min_length": 10,
  "recommended_length": 14,
  "extra_passwords": ["CompanyName2024", "WelcomeToAcme1"],
  "disabled_checks": ["keyboard_run"]
}

$ passlint -config passlint.json config.yaml
```

All fields are optional; anything left out keeps its built-in value
(`min_length: 8`, `recommended_length: 12`, no extra passwords, no disabled
checks). `extra_passwords` adds to, rather than replaces, the built-in list
of ~120 common passwords, and is matched the same way: case-insensitively,
against the whole value. `disabled_checks` turns off checks by name:
`length`, `common`, `char_classes`, `repeated_run`, `keyboard_run`.

An unknown field, an unknown check name, or a `recommended_length` below
`min_length` is a config error, and passlint exits `2` without scanning
anything.

## What it checks

- length (error under 8 characters, warning under 12)
- membership in a list of ~120 passwords that show up repeatedly in breach
  dumps and "worst passwords" roundups
- missing character classes (upper/lower/digit/symbol) when two or more are
  absent
- a character repeated four or more times in a row
- keyboard or numeric runs like `1234` or `qwerty`

## License

MIT, see [LICENSE](LICENSE).
