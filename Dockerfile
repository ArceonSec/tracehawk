FROM python:3.11-alpine3.19

ENV PYTHONUNBUFFERED=1
WORKDIR /app

RUN apk add --no-cache \
    git \
    curl \
    wget \
    bash \
    ca-certificates \
    tar

# semgrep
RUN pip install --no-cache-dir semgrep==1.73.0

# trivy — v0.69.3 is the latest safe release (v0.69.4 was compromised in a supply chain attack on 2026-03-19)
ARG TRIVY_VERSION=0.69.3
RUN wget -O trivy.tar.gz \
    https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz \
 && tar -xzf trivy.tar.gz trivy \
 && mv trivy /usr/local/bin/ \
 && chmod +x /usr/local/bin/trivy \
 && rm trivy.tar.gz

# gitleaks
ARG GITLEAKS_VERSION=8.18.2
RUN wget -O gitleaks.tar.gz \
    https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz \
 && tar -xzf gitleaks.tar.gz \
 && mv gitleaks /usr/local/bin/ \
 && chmod +x /usr/local/bin/gitleaks \
 && rm gitleaks.tar.gz

COPY . .

RUN mkdir -p /output

CMD ["python", "main.py"]