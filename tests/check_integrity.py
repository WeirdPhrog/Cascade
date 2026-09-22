"""The bootstrap installer must accept exactly the manager in this checkout."""
import hashlib
from pathlib import Path
import re

root = Path(__file__).parents[1]
expected = re.search(r"^EXPECTED_SHA256=([0-9a-f]{64})$", (root / "install.sh").read_text(encoding="utf-8"), re.M)
assert expected, "Missing installer hash"
assert hashlib.sha256((root / "cascade.py").read_bytes()).hexdigest() == expected[1]
assert hashlib.sha256((root / "upstream/install.original.sh").read_bytes()).hexdigest() == "84258f802d27cf8f058274dbdb3d1de033f83f067695776d8d25164b53a1f755"
print("PASS: installer and upstream checksums")
