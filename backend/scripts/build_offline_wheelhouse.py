import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shadowtrace.wheelhouse_builder import main


if __name__ == "__main__":
    if not any(arg == "--root" or arg.startswith("--root=") for arg in sys.argv):
        sys.argv.extend(["--root", str(Path(__file__).resolve().parents[1])])
    raise SystemExit(main())
