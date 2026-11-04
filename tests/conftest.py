import sys
from pathlib import Path

# main.py imports "rules" directly, so the src folder needs to be importable
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
