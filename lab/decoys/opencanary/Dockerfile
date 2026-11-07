FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    && pip install --no-cache-dir opencanary \
    && apt-get purge -y gcc libffi-dev libssl-dev \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/opencanaryd /var/log/opencanary

COPY opencanary.conf /etc/opencanaryd/opencanary.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 21 80 3306

ENTRYPOINT ["/entrypoint.sh"]

