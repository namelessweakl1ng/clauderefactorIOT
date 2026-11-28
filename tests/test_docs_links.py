"""Every relative link in every tracked Markdown file must resolve to a real file or folder.

Keeps the documentation navigable after files move.
"""

import re
import subprocess
from pathlib import Path

LINK = re.compile(r"\]\(([^)\s]+)\)")
ROOT = Path(__file__).resolve().parents[1]


def markdown_files():
    out = subprocess.run(["git", "ls-files", "*.md"], capture_output=True, text=True, cwd=ROOT, check=True).stdout.split()
    return [ROOT / f for f in out]


def test_every_relative_markdown_link_resolves():
    broken = []
    for path in markdown_files():
        text = re.sub(r"```.*?```", "", path.read_text(encoding="utf-8"), flags=re.S)  # ignore code blocks
        for target in LINK.findall(text):
            target = target.split("#", 1)[0]
            if not target or re.match(r"^[a-z][a-z0-9+.-]*:", target):
                continue  # pure anchor, or http:, mailto: ...
            if not (path.parent / target).exists():
                broken.append(f"{path.relative_to(ROOT)} -> {target}")
    assert not broken, "broken links:\n" + "\n".join(broken)


def test_every_top_level_folder_explains_itself():
    for folder in ("backend", "frontend", "sensor", "attacks", "evaluation", "elk", "scripts", "tests", "docs"):
        assert (ROOT / folder / "README.md").exists(), f"{folder}/README.md is missing"
