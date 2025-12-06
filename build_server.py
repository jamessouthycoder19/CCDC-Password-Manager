import os
import shutil
import subprocess
from pathlib import Path
import re

# -----------------------------
# CONFIGURATION
# -----------------------------
SOURCE_TEMPLATES = "templates"
SOURCE_STATIC = "static"
BUILD_DIR = "."

SERVER_FILE = "server.py"
NUITKA_ARGS = [
    "--onefile",
]

# -----------------------------
# MAIN BUILD PROCESS
# -----------------------------
def main():
    print("=== Cleaning build directory ===")

    print("=== Running Nuitka ===")
    nuitka_cmd = [
        "python", "-m", "nuitka",
        SERVER_FILE,
        *NUITKA_ARGS,
        "--include-package=OpenSSL",
        f"--include-data-dir={BUILD_DIR}/templates=templates",
        f"--include-data-dir={BUILD_DIR}/static=static",
    ]

    print("Running:", " ".join(nuitka_cmd))
    subprocess.run(nuitka_cmd, check=True)

    print("\n=== Build complete! ===")


if __name__ == "__main__":
    main()