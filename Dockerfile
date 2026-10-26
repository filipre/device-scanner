FROM python:3.14
COPY --from=ghcr.io/astral-sh/uv:0.6.12 /uv /uvx /bin/
RUN apt-get update && apt-get install nmap -y
ENV UV_PYTHON_DOWNLOADS=0 UV_LINK_MODE=copy
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev
COPY scan.py scan.py
RUN touch scan.txt
RUN touch log.txt
CMD ["uv", "run", "--no-sync", "scan.py"]
