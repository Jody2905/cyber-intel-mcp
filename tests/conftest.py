import os
from pathlib import Path

# Always test against the bundled sample, even if you've built a full snapshot in data/snapshot.
os.environ["CYBER_INTEL_DATA_DIR"] = str(
    Path(__file__).resolve().parents[1] / "src" / "cyber_intel_mcp" / "data" / "sample"
)
