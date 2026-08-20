# syntax=docker/dockerfile:1

FROM python:3.11-slim

# Node.js 18+ is required to run scanner/scan.mjs via ts-morph. git is
# required by the repo picker's "add from GitHub" flow (ui/live.py shells
# out to `git clone`).
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl gnupg git \
    && curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Node dependencies (ts-morph) for the AST scanner.
COPY scanner/package.json scanner/package-lock.json ./scanner/
RUN cd scanner && npm install

# Install Python dependencies for the FastAPI app.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the codebase.
COPY . .

EXPOSE 8000

CMD ["uvicorn", "ui.server:app", "--host", "0.0.0.0", "--port", "8000"]
