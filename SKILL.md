---
name: scan-skill-injection
description: Scan skill files for prompt-injection and supply-chain patterns. Run with /scan-skill-injection. Optionally "check name X", "with frontmatter", "include scripts", or "fixtures" for regression test.
---

# Scan Skill Injection

**Command:** `/scan-skill-injection`

Scans SKILL.md (and optionally scripts) for prompt-injection-like text, hidden comments with external requests, dangerous Prerequisites (e.g. curl | bash), obfuscation, and known C2/exfil indicators. Reports file, line, pattern id, and snippet. Exit 0 = clean, 1 = at least one hit (review in context).

## When the user runs this command

1. **Default:** Run the scanner on the skills directory and report the result.
   - From package root: `npm run scan` or `node scripts/scan-skill-injection.cjs --dir skills`
   - If exit 0: report that no patterns were found and how many files were scanned.
   - If exit 1: show the script output (file:line [patternId], snippet) and note that hits are candidates for review; see `docs/skill-prompt-injection.md`.

2. **Check a skill name (blocklist):** If the user says "check name X" or "is X malicious" or gives a skill name to check:
   - Run: `node scripts/scan-skill-injection.cjs --check-name <name>`
   - Report: name is in blocklist (exit 1) or not (exit 0).

3. **Stricter scan (external skill):** If the user says "with frontmatter", "include scripts", or is reviewing a downloaded/external skill:
   - Run with `--frontmatter` and/or `--include-scripts`. For a specific folder: `--dir <path>`.
   - Example: `node scripts/scan-skill-injection.cjs --dir /path/to/skill --frontmatter --include-scripts`

4. **Regression test (fixtures):** If the user says "fixtures" or "test detector":
   - Run: `npm run scan:fixtures` or `node scripts/scan-skill-injection.cjs --dir fixtures`
   - Expected: exit 1 with hits. If exit 0, the detector regressed.

## What you do

- Run the appropriate command from the **package root** (where `scripts/` and `package.json` live). Capture stdout/stderr.
- Summarize: number of files scanned, exit code, and if there are hits list them (file:line [id] and short snippet). Run the command yourself; do not ask the user to run it.

## Reference

- Patterns and options: `docs/skill-prompt-injection.md`
- ClawHavoc context and blocklist: `docs/clawhavoc-reference.md`
