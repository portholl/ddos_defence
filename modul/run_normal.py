#!/usr/bin/env python3
import subprocess
import sys

cmd = [
    sys.executable,
    "generate_stats.py",
    "--mode", "normal",
    "--flows", "10",
    "--tick", "1.0",
    "--seed", "11",
]

subprocess.run(cmd)
