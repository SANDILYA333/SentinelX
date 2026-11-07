#!/bin/bash
# /usr/local/bin/entrypoint-dbsrv.sh
set -e

# Start PostgreSQL service
echo "Starting PostgreSQL service..."
service postgresql start

# Wait until PostgreSQL is ready
for i in $(seq 1 30); do
  if pg_isready -h localhost >/dev/null 2>&1; then
    echo "PostgreSQL is ready."
    break
  fi
  sleep 1
done

# Initialize customer database & bob user if not already done
su - postgres -c "psql -d postgres -c \"
CREATE USER bob WITH SUPERUSER PASSWORD 'BobDatabasePass2026!';
CREATE TABLE IF NOT EXISTS customers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL,
    balance NUMERIC(10, 2) NOT NULL
);
INSERT INTO customers (name, email, balance)
SELECT 'Acme Corp', 'contact@acme.com', 12500.50 WHERE NOT EXISTS (SELECT 1 FROM customers);
INSERT INTO customers (name, email, balance)
SELECT 'Initech LLC', 'peter@initech.com', 8400.00 WHERE NOT EXISTS (SELECT 1 FROM customers WHERE name='Initech LLC');
INSERT INTO customers (name, email, balance)
SELECT 'Umbrella Corp', 'admin@umbrella.com', 99200.75 WHERE NOT EXISTS (SELECT 1 FROM customers WHERE name='Umbrella Corp');
INSERT INTO customers (name, email, balance)
SELECT 'Stark Industries', 'tony@stark.com', 550000.00 WHERE NOT EXISTS (SELECT 1 FROM customers WHERE name='Stark Industries');
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO bob;
\"" >/dev/null 2>&1 || true

# Execute common entrypoint (sshd, wazuh-agent)
exec /usr/local/bin/entrypoint-common.sh "$@"

