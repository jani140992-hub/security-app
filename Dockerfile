FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt || true

COPY . .
RUN pip install --no-cache-dir -e .

EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8443/api/v1/health')" || exit 1

ENTRYPOINT ["python", "-m", "aegisguard.api.app", "8443"]
