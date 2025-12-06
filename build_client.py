import os
import shutil
import subprocess
import re

# -----------------------------
# CONFIGURATION
# -----------------------------
BUILD_DIR = "client_build_assets"

SERVER_FILE = "client.py"
NUITKA_ARGS = [
    "--onefile",
]

# -----------------------------
# MAIN BUILD PROCESS
# -----------------------------
def main():

    print("=== Running Nuitka ===")
    nuitka_cmd = [
        "sudo", "/home/james/password-manager/venv/bin/python3", "-m", "nuitka",
        SERVER_FILE,
        *NUITKA_ARGS,
    ]

    print("Running:", " ".join(nuitka_cmd))
    subprocess.run(nuitka_cmd, check=True)

    print("\n=== Build complete! ===")


if __name__ == "__main__":
    main()
