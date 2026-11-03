# domains2rules

**English** · [Русский](README.ru.md)

Turns a plain domain list into compact AdGuard `$dnsrewrite` rules: instead of
hundreds of `||domain^$dnsrewrite=IP` lines you get a few lines like
`/^([^.]+\.)*(a\.com|(x|y)\.b\.com|…)$/$dnsrewrite=IP`.

No dependencies, Python 3.8+ standard library only.

## Usage

```bash
./domains2rules.py                                  # no arguments: prints help
./domains2rules.py domains.txt -i 1.2.3.4 -o rules.txt
./domains2rules.py domains.txt -i 1.2.3.4 -i 5.6.7.8 -i 9.9.9.9
cat domains.txt | ./domains2rules.py -i 1.2.3.4 > rules.txt
```

| Option | Description |
|---|---|
| `-i`, `--ip IP` | **Required.** IP for `$dnsrewrite`; may be repeated. Output lines follow the argument order |
| `-o`, `--output FILE` | Output file (default: stdout) |
| `--max-len N` | Max length of one rule line in bytes. Default **1024**; `0` = do not split |
| `--no-eol` | Do not add a trailing newline |
| `--no-check` | Skip the self-check |
| `--lang {en,ru}` | Message language. Default: `DOMAINS2RULES_LANG`, then the system locale (`ru*` → Russian, otherwise English) |

## Input format

Anything extra is stripped: `example.com`, `*.example.com`, `||example.com^`,
URLs, hosts lines (`0.0.0.0 example.com`), `#` and `!` comments, empty lines.
IDNs are converted to punycode. Invalid lines are skipped and listed on stderr.

## What it does

- removes duplicates and domains already covered by a listed parent (`api.x.com` when `x.com` is listed);
- groups subdomains: `(a|b|c)\.example\.com`;
- folds numbered series (`dnstest0…10`) and identical names across TLDs (`brand\.(ca|com|net)`);
- splits the rule into chunks of at most `--max-len` bytes, one line per IP for every chunk;
- verifies the result before writing: every domain and its subdomains match, look-alikes
  (`xexample.com`) do not, only RE2-compatible constructs are used.
  On failure the exit code is 1 and nothing is written.

Output order: regex chunk first, then the IPs in the given order.

## About the length limit

1024 bytes is a conservative default. The exact per-rule limit depends on the
AdGuard product and version: if your rules are rejected, lower `--max-len`;
if they are accepted, raise it to get fewer lines.

## Verify

```bash
python3 -m unittest discover -s tests -v
./domains2rules.py examples/domains.txt -i 1.2.3.4
```

Expected: one regex line per IP and `self-check: OK` on stderr.
