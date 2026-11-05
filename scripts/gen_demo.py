# /// script
# requires-python = ">=3.12"
# dependencies = ["rich"]
# ///
"""Regenerate docs/demo.svg: a terminal screenshot of gha-warden on examples/vulnerable.

Run from anywhere with `uv run scripts/gen_demo.py`. The CLI only emits color when
stdout is a TTY, so the child process reports `isatty() == True`; the report itself
is still produced by the real CLI entry point.
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys
from pathlib import Path

# rich comes from the PEP 723 header above, not from the project environment ty checks.
from rich.console import Console  # ty: ignore[import-not-found]
from rich.text import Text  # ty: ignore[import-not-found]

ROOT = Path(__file__).resolve().parent.parent
TARGET = "examples/vulnerable"
OUTPUT = ROOT / "docs" / "demo.svg"
WIDTH = 120

# Run the CLI as if attached to a terminal so it emits its ANSI colors.
CHILD = (
    "import sys; sys.stdout.isatty = lambda: True; "
    "from gha_warden.cli import main; sys.exit(main(sys.argv[1:]))"
)


def run_cli() -> str:
    uv = shutil.which("uv") or sys.exit("uv not found on PATH")
    env = {k: v for k, v in os.environ.items() if k != "NO_COLOR"}
    env["PYTHONUTF8"] = "1"
    result = subprocess.run(  # noqa: S603 - fixed argument list, no shell
        [uv, "run", "--project", str(ROOT), "python", "-c", CHILD, TARGET],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    if result.returncode not in (0, 1):
        sys.exit(f"gha-warden failed ({result.returncode}):\n{result.stderr}")
    return result.stdout.rstrip("\n")


def main() -> None:
    console = Console(
        record=True,
        width=WIDTH,
        force_terminal=True,
        color_system="truecolor",
        file=io.StringIO(),
    )
    console.print(Text.assemble(("$ ", "bold green"), f"gha-warden {TARGET}"))
    console.print(Text.from_ansi(run_cli()), no_wrap=True, overflow="ellipsis")
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    console.save_svg(str(OUTPUT), title="gha-warden")
    print(f"wrote {OUTPUT.relative_to(ROOT).as_posix()}")


if __name__ == "__main__":
    main()
