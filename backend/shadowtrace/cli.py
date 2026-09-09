def run_pipeline_main() -> int:
    import argparse
    from pathlib import Path

    from .pipeline import ShadowTracePipeline

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
        print(f"rows_processed={count}")
        print(f"alerts={pipeline.store.count_alerts()}")
    finally:
        pipeline.store.close()
    return 0


def verify_offline_main() -> int:
    from .offline_verify import main

    return main()


def audit_artifacts_main() -> int:
    from .artifact_audit import main

    return main()


def verify_bundle_main() -> int:
    from .bundle_manifest import main

    return main()


def build_bundle_main() -> int:
    from .release_bundle import main

    return main()


def build_wheelhouse_main() -> int:
    from .wheelhouse_builder import main

    return main()
