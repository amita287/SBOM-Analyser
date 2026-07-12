# syntax=docker/dockerfile:1
FROM python:3.13-slim

WORKDIR /app

# Dependencies first, so a code edit doesn't re-resolve the whole tree.
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir -e .

# The dataset is part of the image: the app analyses it on boot and has nothing
# to serve without it.
COPY data/ ./data/
COPY scripts/ ./scripts/

# The API self-bootstraps — with no reports/analysis.json it analyses data/ during
# startup — so there is no build step to forget and no "POST /analyze first" 404
# waiting for the first visitor.
ENV LLM_PROVIDER=none
EXPOSE 8000

# $PORT is what Render / Railway / Fly inject. Default to 8000 for `docker run`.
CMD ["sh", "-c", "uvicorn sbom_analyzer.api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
