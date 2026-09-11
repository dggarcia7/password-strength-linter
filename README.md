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

passlint exits `1` if it reported any findings, `2` if a file couldn't be
opened, and `0` if the input was clean, so it can be used as a CI gate.

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
