-- Test "company database": schema, tables and sample data.
-- Idempotent: safe to run many times. {schema} is filled in with psycopg.sql.Identifier.

CREATE SCHEMA IF NOT EXISTS {schema};

CREATE TABLE IF NOT EXISTS {schema}.customers (
    id         integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name       text        NOT NULL,
    email      text        NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS {schema}.products (
    id    integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    sku   text          NOT NULL UNIQUE,
    title text          NOT NULL,
    price numeric(10,2) NOT NULL CHECK (price >= 0)
);

CREATE TABLE IF NOT EXISTS {schema}.orders (
    id          integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    customer_id integer     NOT NULL REFERENCES {schema}.customers (id),
    product_id  integer     NOT NULL REFERENCES {schema}.products (id),
    quantity    integer     NOT NULL CHECK (quantity > 0),
    created_at  timestamptz NOT NULL DEFAULT now()
);

INSERT INTO {schema}.customers (name, email) VALUES
    ('Alice Example', 'alice@example.com'),
    ('Bob Example',   'bob@example.com'),
    ('Carol Example', 'carol@example.com')
ON CONFLICT (email) DO NOTHING;

INSERT INTO {schema}.products (sku, title, price) VALUES
    ('SKU-001', 'Keyboard', 49.90),
    ('SKU-002', 'Mouse',    19.50),
    ('SKU-003', 'Monitor', 199.00)
ON CONFLICT (sku) DO NOTHING;

INSERT INTO {schema}.orders (customer_id, product_id, quantity)
SELECT c.id, p.id, 1
FROM {schema}.customers c
JOIN {schema}.products p ON p.sku = 'SKU-001'
WHERE NOT EXISTS (SELECT 1 FROM {schema}.orders);
