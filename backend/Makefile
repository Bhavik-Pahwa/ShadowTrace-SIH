.PHONY: install-offline sample test audit-artifacts verify verify-strict verify-linux-target run smoke-api wheelhouse bundle-offline verify-bundle

install-offline:
	pip install --no-index --find-links ./wheelhouse -r requirements.txt
	pip install --no-index --find-links ./wheelhouse -r requirements-pyg-extensions.txt
	pip install --no-build-isolation --no-deps -e .

sample:
	python scripts/run_pipeline.py --sample

test:
	python -m pytest tests

audit-artifacts:
	python scripts/audit_prd_artifacts.py

verify:
	python scripts/verify_offline.py --runtime
	python scripts/run_pipeline.py --sample
	python scripts/audit_prd_artifacts.py
	python -m pytest tests

verify-strict:
	python scripts/verify_offline.py --strict --runtime
	python scripts/run_pipeline.py --sample
	python scripts/audit_prd_artifacts.py
	python -m pytest tests

verify-linux-target:
	bash scripts/verify_linux_target.sh

run:
	uvicorn shadowtrace.main:app --host 0.0.0.0 --port 8000

smoke-api:
	python scripts/smoke_api.py

wheelhouse:
	python scripts/build_offline_wheelhouse.py

bundle-offline:
	python scripts/build_release_bundle.py

verify-bundle:
	python scripts/verify_bundle_manifest.py shadowtrace-xai-offline-bundle.zip
