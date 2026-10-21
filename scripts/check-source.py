#!/usr/bin/env python3
"""Check public source boundaries and local documentation links (stdlib only)."""
import re
import subprocess
import sys
import unicodedata
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def source_paths():
    result = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT
    )
    return sorted({Path(p.decode()) for p in result.split(b"\0") if p and (ROOT / p.decode()).is_file()})


def anchors(path):
    found, counts = set(), {}
    fenced = False
    for line in path.read_text().splitlines():
        if line.lstrip().startswith(("```", "~~~")):
            fenced = not fenced
        if fenced or not re.match(r"^#{1,6}\s", line):
            continue
        heading = re.sub(r"^#+\s+|\s+#+\s*$", "", line).strip().lower()
        heading = re.sub(r"[`*_]", "", heading)
        slug = "".join(c for c in heading if c in " -_" or unicodedata.category(c)[0] in "LN")
        slug = slug.replace(" ", "-")
        n = counts.get(slug, 0)
        counts[slug] = n + 1
        found.add(slug if n == 0 else f"{slug}-{n}")
    return found


def check(paths):
    errors = []
    private_names = re.compile(
        r"^(?:users\.json.*|rules\.json.*|hosts\.json.*|hosts\.key|api-keys\.json.*|"
        r"(?:security|monitoring)-policy\.json.*|audit\.jsonl.*|rollback\.json.*|"
        r"agent\.identity|agent\.key\.sha256|interview-guide\.md|xmjs\.md)$"
    )
    private_dirs = {"data", "bin", "dist", "output", ".playwright-cli", "test-results", "playwright-report"}
    path_set = {p.as_posix() for p in paths}
    for relative in paths:
        name = relative.name
        if (ROOT / relative).is_symlink():
            errors.append(f"symbolic link requires explicit publication review: {relative}")
            continue
        if (relative.parts[0] in private_dirs or "__pycache__" in relative.parts or private_names.match(name)
                or (name.startswith(".env") and not name.endswith(".example"))
                or relative.suffix.lower() in {".pem", ".key", ".p12", ".pfx", ".log", ".pid", ".pyc"}):
            errors.append(f"private/runtime file in source: {relative}")
        if relative.suffix != ".md":
            continue
        path = ROOT / relative
        content = path.read_text()
        # Inline Markdown links, HTML screenshot links, and reference definitions.
        links = re.findall(r"!?\[[^\]\n]*\]\(([^)\n]+)\)", content)
        links += re.findall(r'(?:href|src)=[\"\']([^\"\']+)[\"\']', content)
        links += re.findall(r"^\[[^\]]+\]:\s*(\S+)", content, re.M)
        for link in links:
            link = link.split(' "', 1)[0].strip().strip("<>")
            parsed = urlsplit(link)
            if parsed.scheme or parsed.netloc:
                continue
            target = (path.parent / unquote(parsed.path)).resolve() if parsed.path else path
            try:
                target_relative = target.relative_to(ROOT).as_posix()
            except ValueError:
                errors.append(f"{relative}: link leaves repository: {link}")
                continue
            if target_relative not in path_set:
                errors.append(f"{relative}: link missing from public source: {link}")
            elif parsed.fragment and target.suffix == ".md" and unquote(parsed.fragment) not in anchors(target):
                errors.append(f"{relative}: missing section: {link}")
        for ref in re.findall(r"`((?:cmd|internal|web|assets|scripts|deploy)/[^`\s]+)`", content):
            # Literal source references; wildcards and release-relative examples are prose.
            if any(c in ref for c in "*<>{}") or ref.endswith("/"):
                continue
            if ref not in path_set:
                errors.append(f"{relative}: source reference missing: {ref}")
    return errors


if __name__ == "__main__":
    paths = source_paths()
    errors = check(paths)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        sys.exit(1)
    print(f"Public source boundaries and documentation links verified ({len(paths)} files)")
