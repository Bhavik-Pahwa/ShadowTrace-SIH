import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shadowtrace.pipeline import ShadowTracePipeline


def main() -> int:
    parser = argparse.ArgumentParser(description="Run ShadowTrace-XAI ingest -> graph -> GNN -> XAI pipeline.")
    parser.add_argument("--input", type=Path, help="CSV/JSON ingest file")
    parser.add_argument("--sample", action="store_true", help="Load deterministic semi-synthetic sample data")
    args = parser.parse_args()
    pipeline = ShadowTracePipeline()
    try:
        if args.sample:
            count = pipeline.load_sample()
        elif args.input:
            count = pipeline.ingest_file(args.input)
        else:
            parser.error("Provide --input PATH or --sample")
        alert_count = pipeline.store.count_alerts()
        print(f"rows_processed={count}")
        print(f"alerts={alert_count}")
    finally:
        pipeline.store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
