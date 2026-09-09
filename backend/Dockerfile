FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libharfbuzz-subset0 \
        libffi-dev \
        shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
COPY requirements-pyg-extensions.txt /app/requirements-pyg-extensions.txt
COPY wheelhouse /app/wheelhouse
RUN pip install --no-cache-dir --no-index --find-links /app/wheelhouse -r /app/requirements.txt \
    && pip install --no-cache-dir --no-index --find-links /app/wheelhouse -r /app/requirements-pyg-extensions.txt

COPY . /app
RUN pip install --no-cache-dir --no-build-isolation --no-deps .

CMD ["uvicorn", "shadowtrace.main:app", "--host", "0.0.0.0", "--port", "8000"]
