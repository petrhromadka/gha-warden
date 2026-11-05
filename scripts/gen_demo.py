# /// script
# requires-python = ">=3.12"
# dependencies = ["rich"]
# ///
"""Regenerate docs/demo.svg: a terminal screenshot of gha-warden on a few example workflows.

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

from rich.console import Console
from rich.text import Text

ROOT = Path(__file__).resolve().parent.parent
# A few files keep the screenshot short enough to read in the README.
TARGETS = [
    "examples/vulnerable/script-injection.yml",
    "examples/vulnerable/pwn-request.yml",
    "examples/vulnerable/images-and-compromised.yml",
]
PROMPT = "gha-warden examples/vulnerable/{script-injection,pwn-request,images-and-compromised}.yml"
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
        [uv, "run", "--project", str(ROOT), "python", "-c", CHILD, *TARGETS],
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
    console.print(Text.assemble(("$ ", "bold green"), PROMPT))
    console.print(Text.from_ansi(run_cli()), no_wrap=True, overflow="ellipsis")
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    console.save_svg(str(OUTPUT), title="gha-warden")
    # save_svg writes platform line endings; keep the committed file LF everywhere.
    OUTPUT.write_bytes(OUTPUT.read_bytes().replace(b"\r\n", b"\n"))
    print(f"wrote {OUTPUT.relative_to(ROOT).as_posix()}")


if __name__ == "__main__":
    main()
