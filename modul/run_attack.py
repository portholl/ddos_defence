#!/usr/bin/env python3
import subprocess
import sys

cmd = [
    sys.executable,
    "generate_stats.py",
    "--mode", "attack",
    "--flows", "10",
    "--tick", "1.0",
    "--seed", "17",
]

subprocess.run(cmd)
