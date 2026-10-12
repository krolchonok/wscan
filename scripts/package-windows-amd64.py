#!/usr/bin/env python3
"""Build and package the Windows amd64 release on Linux or Windows."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile


def main():
    root = Path(__file__).resolve().parent.parent
    version = sys.argv[1] if len(sys.argv) > 1 else "dev"
    if not re.fullmatch(r"[A-Za-z0-9._-]+", version):
        raise SystemExit("Version must contain only letters, digits, dots, underscores or hyphens")
    out = root / "dist"
    out.mkdir(exist_ok=True)
    archive = out / f"wscan-{version}-windows-amd64.zip"
    with tempfile.TemporaryDirectory(prefix="wscan-windows-") as stage:
        bundle = Path(stage) / "wscan-windows-amd64"
        bundle.mkdir()
        env = dict(os.environ, CGO_ENABLED="0", GOOS="windows", GOARCH="amd64")
        subprocess.run([
            "go", "build", "-buildvcs=false", "-trimpath",
            f"-ldflags=-s -w -X main.version={version}",
            "-o", str(bundle / "wscan.exe"), ".",
        ], cwd=root, env=env, check=True)
        shutil.copy2(root / "start.cmd", bundle / "start.cmd")
        shutil.copytree(root / "tools" / "winpeas", bundle / "tools" / "winpeas")
        for name in ["TRANSFER", "WINDOWS", "KNOWN_TEST_FAILURES", "ENGINE_POLICY_AUDIT",
                     "SUPPORTED", "COERCION", "RESULTS", "GUI_REFACTOR"]:
            shutil.copy2(root / "docs" / f"{name}.md", bundle / f"{name}.md")
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
            for path in sorted(bundle.rglob("*")):
                if path.is_file():
                    output.write(path, path.relative_to(stage).as_posix())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    Path(str(archive) + ".sha256").write_text(f"{digest}  {archive.name}\n", encoding="ascii")
    print(archive)


if __name__ == "__main__":
    main()
