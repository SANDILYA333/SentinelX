FROM python:3.12-slim-bookworm

RUN pip install --no-cache-dir pymodbus==3.6.8

WORKDIR /app
COPY server.py /app/server.py

RUN mkdir -p /var/log/plc

EXPOSE 502

CMD ["python", "/app/server.py"]
