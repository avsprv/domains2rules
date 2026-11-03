#!/usr/bin/env python3
"""
domains2rules.py - turn a plain domain list into compact AdGuard regex rules
($dnsrewrite) / простой список доменов -> компактные regex-правила AdGuard.

Run without arguments for help (English or Russian, see --lang).
Запусти без аргументов, чтобы увидеть справку (English / русский, см. --lang).
"""
import argparse
import os
import re
import sys
from collections import defaultdict

LANGS = ("en", "ru")

MESSAGES = {
    "en": {
        "description": """\
Simple domain list -> compact AdGuard regex rules ($dnsrewrite),
one line per IP address.

The IP address is mandatory (--ip, may be repeated; output order = argument order).
Long rules are split into chunks of at most 1024 bytes (--max-len).

Examples:
  ./domains2rules.py domains.txt --ip 1.2.3.4 -o rules.txt
  ./domains2rules.py domains.txt --ip 1.2.3.4 --ip 5.6.7.8 --ip 9.9.9.9
  cat domains.txt | ./domains2rules.py --ip 1.2.3.4 > rules.txt
  ./domains2rules.py domains.txt --ip 1.2.3.4 --max-len 0   # single line

Input format (everything extra is stripped automatically):
  example.com | *.example.com | ||example.com^ | https://example.com/path
  0.0.0.0 example.com (hosts) | comments # and ! | empty lines

No dependencies, Python 3.8+ standard library only.""",
        "input": "domain list file (default: stdin)",
        "output": "output file (default: stdout)",
        "ip": "IP address for $dnsrewrite (REQUIRED, at least one); may be repeated - "
              "output lines follow the argument order",
        "max_len": "max length of one rule line in bytes (default: 1024); long rules are "
                   "split into several lines, 0 = do not split",
        "no_eol": "do not add a trailing newline to the output",
        "no_check": "skip the built-in self-check",
        "lang": "message language (default: from DOMAINS2RULES_LANG or the system locale)",
        "ip_required": "at least one IP is required: --ip IP",
        "max_len_negative": "--max-len must not be negative",
        "bad_ip": "Invalid IP address: {ip}",
        "no_domains": "No valid domains found in the input",
        "check_failed": "Self-check failed:",
        "check_miss": "NOT matched: {name}",
        "check_fp": "false positive: {name}",
        "check_re2": "regex contains constructs that RE2 does not support",
        "summary": "Domains in: {total}, unique: {unique}, after removing redundant: {kept}; "
                   "regex chunks: {chunks}; output lines: {lines}; "
                   "longest line: {longest} bytes; self-check: {check}",
        "check_ok": "OK",
        "check_off": "skipped",
        "redundant": "Redundant (covered by a parent domain): {items}",
        "skipped": "Skipped as invalid: {items}",
    },
    "ru": {
        "description": """\
Простой список доменов -> компактные regex-правила AdGuard ($dnsrewrite),
по одной строке на каждый IP.

IP обязателен (--ip, можно несколько раз; порядок строк = порядок аргументов).
Длинное правило автоматически режется на куски до 1024 байт (--max-len).

Примеры:
  ./domains2rules.py domains.txt --ip 1.2.3.4 -o rules.txt
  ./domains2rules.py domains.txt --ip 1.2.3.4 --ip 5.6.7.8 --ip 9.9.9.9
  cat domains.txt | ./domains2rules.py --ip 1.2.3.4 > rules.txt
  ./domains2rules.py domains.txt --ip 1.2.3.4 --max-len 0   # одной строкой

Входной формат (всё лишнее вычищается автоматически):
  example.com | *.example.com | ||example.com^ | https://example.com/path
  0.0.0.0 example.com (hosts) | комментарии # и ! | пустые строки

Зависимостей нет, только стандартная библиотека Python 3.8+.""",
        "input": "файл со списком доменов (по умолчанию stdin)",
        "output": "выходной файл (по умолчанию stdout)",
        "ip": "IP для $dnsrewrite (ОБЯЗАТЕЛЬНО, минимум один); можно повторять - "
              "порядок строк в выводе совпадает с порядком аргументов",
        "max_len": "макс. длина одной строки-правила в байтах (по умолчанию 1024); "
                   "длинное правило разбивается на несколько, 0 - не разбивать",
        "no_eol": "не добавлять перевод строки в конец файла",
        "no_check": "пропустить самопроверку",
        "lang": "язык сообщений (по умолчанию: DOMAINS2RULES_LANG или локаль системы)",
        "ip_required": "нужен минимум один IP: --ip IP",
        "max_len_negative": "--max-len не может быть отрицательным",
        "bad_ip": "Некорректный IP: {ip}",
        "no_domains": "Во входных данных нет ни одного корректного домена",
        "check_failed": "Самопроверка не пройдена:",
        "check_miss": "НЕ совпал: {name}",
        "check_fp": "ложное срабатывание: {name}",
        "check_re2": "regex содержит конструкции, неподдерживаемые RE2",
        "summary": "Доменов на входе: {total}, уникальных: {unique}, "
                   "после удаления избыточных: {kept}; regex-кусков: {chunks}; "
                   "строк в выводе: {lines}; макс. длина строки: {longest} байт; "
                   "самопроверка: {check}",
        "check_ok": "OK",
        "check_off": "пропущена",
        "redundant": "Избыточные (покрыты родителем): {items}",
        "skipped": "Пропущено как некорректное: {items}",
    },
}

# Two-level suffixes only affect how well the output compresses, never
# correctness: a miss here just gives a slightly less compact (still valid) regex.
SECOND_LEVEL = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.nz", "co.jp", "ne.jp", "or.jp", "com.cn", "net.cn", "org.cn",
    "com.tw", "com.hk", "com.sg", "com.my", "com.br", "com.ar", "com.mx",
    "com.tr", "com.ua", "com.pl", "com.kh", "com.vn", "com.ph", "com.pk",
    "com.eg", "com.sa", "com.ru", "co.in", "co.kr", "co.za", "co.il", "co.id",
}

LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

HEAD = r"^([^.]+\.)*("
TAIL = r")$"


def detect_lang(argv):
    """--lang value > DOMAINS2RULES_LANG > system locale (ru* -> ru) > en."""
    for i, a in enumerate(argv):
        if a.startswith("--lang="):
            v = a.split("=", 1)[1]
        elif a == "--lang" and i + 1 < len(argv):
            v = argv[i + 1]
        else:
            continue
        if v in LANGS:
            return v
    env = os.environ.get("DOMAINS2RULES_LANG", "").lower()
    if env in LANGS:
        return env
    loc = (os.environ.get("LC_ALL") or os.environ.get("LC_MESSAGES")
           or os.environ.get("LANG") or "")
    return "ru" if loc.lower().startswith("ru") else "en"


def normalize(line):
    """Input line -> lowercase domain, or None if it is not a valid domain."""
    s = re.split(r"[#!]", line, maxsplit=1)[0].strip().lower()
    if not s:
        return None
    parts = s.split()
    if len(parts) > 1 and (IPV4.match(parts[0]) or parts[0] == "::1"):
        s = parts[1]                                  # hosts format
    elif len(parts) > 1:
        return None
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s)       # scheme
    s = re.split(r"[/?:\^$]", s.lstrip("|"), maxsplit=1)[0]  # path, port, ^, $
    s = s.lstrip("*.").rstrip(".")                    # *.example.com, .example.com
    try:
        s = s.encode("idna").decode("ascii")          # IDN -> punycode
    except UnicodeError:
        return None
    labels = s.split(".")
    if len(labels) < 2 or IPV4.match(s):
        return None
    if not all(LABEL.match(x) for x in labels):
        return None
    return s


def esc(x):
    return x.replace(".", "\\.")


def split_reg(d):
    """a.b.label.suffix -> (sub, label, suffix); sub may be ''."""
    p = d.split(".")
    n = 2 if ".".join(p[-2:]) in SECOND_LEVEL and len(p) > 2 else 1
    suffix = ".".join(p[-n:])
    label = p[-n - 1]
    sub = ".".join(p[: -n - 1])
    return sub, label, suffix


def prune(domains):
    """Drop domains already covered by a listed parent (a.b.com if b.com is listed)."""
    s = set(domains)
    keep, dropped = [], []
    for d in sorted(s):
        p = d.split(".")
        if any(".".join(p[i:]) in s for i in range(1, len(p) - 1)):
            dropped.append(d)
        else:
            keep.append(d)
    return keep, dropped


def build_alternatives(domains):
    regs = defaultdict(set)                    # (label, suffix) -> {sub, ...}
    for d in domains:
        sub, label, suffix = split_reg(d)
        regs[(label, suffix)].add(sub)

    alts = []
    whole = []                                 # (label, suffix): the domain itself
    for (label, suffix), subs in regs.items():
        if "" in subs:
            whole.append((label, suffix))
        else:
            base = esc(f"{label}.{suffix}")
            subs = sorted(subs)
            if len(subs) == 1:
                alts.append(esc(subs[0]) + "\\." + base)
            else:
                alts.append("(" + "|".join(esc(x) for x in subs) + ")\\." + base)

    # A) dnstest0..10 -> dnstest(0|1|...|10); plain groups only, no [0-9]
    numeric = defaultdict(list)
    rest = []
    for label, suffix in whole:
        m = re.match(r"^(.*[^0-9])([0-9]+)$", label)
        if m:
            numeric[(m.group(1), suffix)].append(m.group(2))
        else:
            rest.append((label, suffix))
    for (prefix, suffix), nums in numeric.items():
        if len(nums) < 3:
            rest += [(prefix + n, suffix) for n in nums]
            continue
        nums = sorted(nums, key=lambda x: (int(x), x))
        alts.append(esc(prefix) + "(" + "|".join(nums) + ")" + "\\." + esc(suffix))

    # B) brand.ca, brand.sk, ... -> brand\.(ca|sk|...)
    by_label = defaultdict(list)
    for label, suffix in rest:
        by_label[label].append(suffix)
    for label, suffixes in by_label.items():
        suffixes = sorted(suffixes)
        if len(suffixes) == 1:
            alts.append(esc(f"{label}.{suffixes[0]}"))
        else:
            alts.append(esc(label) + "\\.(" + "|".join(esc(x) for x in suffixes) + ")")

    alts.sort(key=lambda x: x.lstrip("("))
    return alts


def covered(name, domain_set):
    p = name.split(".")
    return any(".".join(p[i:]) in domain_set for i in range(len(p) - 1))


def split_chunks(alts, max_len, ip_len=15):
    """Split alternatives so every rule line is <= max_len bytes (0 = no limit)."""
    if not max_len:
        return [alts]
    overhead = len("/" + HEAD + TAIL + "/$dnsrewrite=") + ip_len
    chunks, cur, size = [], [], overhead
    for a in alts:
        add = len(a) + (1 if cur else 0)
        if cur and size + add > max_len:
            chunks.append(cur)
            cur, size = [], overhead
            add = len(a)
        cur.append(a)
        size += add
    if cur:
        chunks.append(cur)
    return chunks


def self_check(regexes, domains, m):
    """Every domain and its subdomains must match at least one regex;
    'x'+domain and domain+'.invalid' must not (unless covered by a parent)."""
    rxs = [re.compile(r) for r in regexes]
    hit = lambda name: any(rx.match(name) for rx in rxs)
    dset = set(domains)
    errors = []
    for d in domains:
        for name in (d, "sub." + d, "a.b." + d):
            if not hit(name):
                errors.append(m["check_miss"].format(name=name))
        for name in ("x" + d, d + ".invalid"):
            if hit(name) != covered(name, dset):
                errors.append(m["check_fp"].format(name=name))
    if any(re.search(r"\(\?|\\[1-9]", r) for r in regexes):
        errors.append(m["check_re2"])
    return errors


def only_lang_args(argv):
    """True if argv holds nothing except --lang [value]."""
    rest, skip = [], False
    for i, a in enumerate(argv):
        if skip:
            skip = False
        elif a == "--lang":
            skip = True
        elif not a.startswith("--lang="):
            rest.append(a)
    return not rest


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    lang = detect_lang(argv)
    m = MESSAGES[lang]

    ap = argparse.ArgumentParser(prog="domains2rules.py", description=m["description"],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", nargs="?", default="-", help=m["input"])
    ap.add_argument("-o", "--output", default="-", help=m["output"])
    ap.add_argument("-i", "--ip", action="append", metavar="IP", help=m["ip"])
    ap.add_argument("--max-len", type=int, default=1024, metavar="N", help=m["max_len"])
    ap.add_argument("--no-eol", action="store_true", help=m["no_eol"])
    ap.add_argument("--no-check", action="store_true", help=m["no_check"])
    ap.add_argument("--lang", choices=LANGS, default=lang, help=m["lang"])

    if only_lang_args(argv):
        ap.print_help()
        return
    args = ap.parse_args(argv)
    if not args.ip:
        ap.error(m["ip_required"])
    if args.max_len < 0:
        ap.error(m["max_len_negative"])

    ips = args.ip
    for ip in ips:
        if not IPV4.match(ip) or any(int(o) > 255 for o in ip.split(".")):
            sys.exit(m["bad_ip"].format(ip=ip))

    src = sys.stdin if args.input == "-" else open(args.input, encoding="utf-8")
    domains, skipped = [], []
    for line in src.read().splitlines():
        if not line.strip() or line.strip()[0] in "#!":
            continue
        d = normalize(line)
        (domains if d else skipped).append(d or line.strip())
    if not domains:
        sys.exit(m["no_domains"])

    unique = sorted(set(domains))
    kept, dropped = prune(unique)
    chunks = split_chunks(build_alternatives(kept), args.max_len)
    regexes = [HEAD + "|".join(c) + TAIL for c in chunks]

    if not args.no_check:
        errors = self_check(regexes, kept, m)
        if errors:
            sys.exit(m["check_failed"] + "\n" + "\n".join(errors[:20]))

    # order: regex chunk first, then the IPs in the given order
    lines = [f"/{rx}/$dnsrewrite={ip}" for rx in regexes for ip in ips]
    out = "\n".join(lines) + ("" if args.no_eol else "\n")
    if args.output == "-":
        sys.stdout.write(out)
    else:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)

    print(m["summary"].format(
        total=len(domains), unique=len(unique), kept=len(kept), chunks=len(regexes),
        lines=len(lines), longest=max(map(len, lines)),
        check=m["check_off"] if args.no_check else m["check_ok"]), file=sys.stderr)
    if dropped:
        print(m["redundant"].format(items=", ".join(dropped)), file=sys.stderr)
    if skipped:
        print(m["skipped"].format(items=", ".join(skipped[:20])), file=sys.stderr)


if __name__ == "__main__":
    main()
