# Dockerfile for PAW Encrypted Clicking Module
# Provides isolated, secure environment for phishing analysis

FROM python:3.11-slim

# Install Chrome and dependencies
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    unzip \
    && wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - \
    && echo "deb http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list \
    && apt-get update \
    && apt-get install -y google-chrome-stable \
    && rm -rf /var/lib/apt/lists/*

# Install Chromedriver
RUN CHROME_VERSION=$(google-chrome --version | awk '{print $3}' | cut -d'.' -f1) \
    && wget -q "https://chromedriver.storage.googleapis.com/LATEST_RELEASE_${CHROME_VERSION}" -O /tmp/version \
    && DRIVER_VERSION=$(cat /tmp/version) \
    && wget -q "https://chromedriver.storage.googleapis.com/${DRIVER_VERSION}/chromedriver_linux64.zip" -O /tmp/chromedriver.zip \
    && unzip /tmp/chromedriver.zip -d /usr/local/bin/ \
    && rm /tmp/chromedriver.zip \
    && chmod +x /usr/local/bin/chromedriver

# Create non-root user for security
RUN useradd -m -u 1000 pawuser && \
    mkdir -p /mnt/crypto_vault && \
    chown pawuser:pawuser /mnt/crypto_vault

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY paw/ ./paw/
COPY setup.py pyproject.toml README.md LICENSE ./

# Install PAW package
RUN pip install -e .

# Switch to non-root user
USER pawuser

# Create tmpfs mount point for Chrome
VOLUME ["/tmp", "/mnt/crypto_vault"]

# Environment variables (override at runtime)
ENV CRYPTO_PASSWORD="" \
    CRYPTO_VAULT_PATH="/mnt/crypto_vault" \
    CHROME_BIN="/usr/bin/google-chrome" \
    CHROMEDRIVER_PATH="/usr/local/bin/chromedriver"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "from paw.modules.encrypted_clicking.encrypted_clicker import EncryptedClickAnalyzer; print('OK')" || exit 1

# Default command
ENTRYPOINT ["python", "-m", "paw.modules.encrypted_clicking.encrypted_clicker"]
CMD ["--help"]
