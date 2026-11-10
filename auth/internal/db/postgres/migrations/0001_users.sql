CREATE TABLE IF NOT EXISTS users (
    id            uuid        PRIMARY KEY,
    email         text        NOT NULL,
    password_hash text        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    -- сервис хранит email нормализованными; это гарантирует честность уникального индекса
    CONSTRAINT users_email_lowercase CHECK (email = lower(email))
);

CREATE UNIQUE INDEX IF NOT EXISTS users_email_key ON users (email);
