# Threat Hunting microservice — Scrapling (stealth browser) + OpenRouter + Pydantic.
# Sized for Hugging Face Spaces (Docker SDK): listens on 7860.
FROM python:3.12-slim

# Scrapling's browser fetchers (camoufox/Playwright) need these system libs.
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget ca-certificates fonts-liberation libnss3 libnspr4 libatk1.0-0 \
    libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 libxcomposite1 \
    libxdamage1 libxfixes3 libxrandr2 libgbm1 libasound2 libpango-1.0-0 \
    libcairo2 libatspi2.0-0 \
 && rm -rf /var/lib/apt/lists/*

ENV HOME=/app \
    PYTHONUNBUFFERED=1 \
    PORT=7860

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download the stealth browser Scrapling drives (camoufox/playwright chromium).
RUN scrapling install || python -m playwright install chromium || true

COPY . .

EXPOSE 7860

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7860"]
