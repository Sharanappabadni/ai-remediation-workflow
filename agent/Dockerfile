FROM python:3.10-slim

WORKDIR /app

# Install system deps + npm
RUN apt-get update && \
    apt-get install -y wget gnupg lsb-release ca-certificates curl npm && \
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb bookworm main" > /etc/apt/sources.list.d/trivy.list && \
    apt-get update && \
    apt-get install -y trivy

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt pipdeptree

COPY main.py .

CMD ["uvicorn","main:app","--host","0.0.0.0","--port","8000"]