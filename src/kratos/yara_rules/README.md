# Bundled starter YARA ruleset

Kratos's `run_yara_scan` tool uses this directory as its default ruleset (every `.yar`/`.yara`
file here is concatenated and pushed to the target for scanning). This is a small starter set,
not a maintained/updated feed — no rule-management system exists or is planned; pass `rules_path`
to `run_yara_scan` to use a custom ruleset instead.

## Source

Both files are vendored, unmodified, from the [Yara-Rules/rules](https://github.com/Yara-Rules/rules)
project — a long-running, widely-used, reputable public collection of open YARA rules — fetched
2026-07-14:

- **`MALW_Eicar.yar`** — `malware/MALW_Eicar.yar`. Detects the [EICAR standard antivirus test
  file](https://en.wikipedia.org/wiki/EICAR_test_file), the industry-standard safe test string
  used to verify AV/scanning tools work without needing real malware. Author: Marc Rivero
  (@seifreed).
- **`WShell_ChinaChopper.yar`** — `webshells/WShell_ChinaChopper.yar`. Detects the "China Chopper"
  webshell (ASPX and PHP variants), a real, well-documented threat (see the rule's own
  `reference1` field — FireEye's 2013 writeup). Author: Ryan Boyle.

## License

The Yara-Rules project is licensed under GNU GPLv2. These two files are included as data
(consumed by the separately GPL-licensed `yara` binary at scan time on the target, not compiled
or linked into Kratos itself) with their original attribution/license headers preserved
unmodified. The full GPLv2 text is in `LICENSE` in this directory (copied from
`https://github.com/Yara-Rules/rules/blob/master/LICENSE`).
