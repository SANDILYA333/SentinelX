FROM python:3.12-slim-bookworm

RUN pip install --no-cache-dir pymodbus==3.6.8

WORKDIR /app
COPY sim.py /app/sim.py

RUN mkdir -p /var/log/plc

EXPOSE 502 8080

CMD ["python", "/app/sim.py"]
