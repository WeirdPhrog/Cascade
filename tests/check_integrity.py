"""The bootstrap installer must accept exactly the manager in this checkout."""
import hashlib
from pathlib import Path
import re

root = Path(__file__).parents[1]
expected = re.search(r"^EXPECTED_SHA256=([0-9a-f]{64})$", (root / "install.sh").read_text(encoding="utf-8"), re.M)
assert expected, "Missing installer hash"
assert hashlib.sha256((root / "cascade.py").read_bytes()).hexdigest() == expected[1]
print("PASS: installer checksum")
