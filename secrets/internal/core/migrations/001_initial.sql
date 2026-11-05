CREATE TABLE secrets (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL,
    owner_email TEXT NOT NULL,
    title TEXT NOT NULL CHECK (length(title) > 0),
    ciphertext BYTEA NOT NULL,
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 12),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX secrets_owner_idx ON secrets(owner_id, created_at DESC);
CREATE INDEX secrets_expiry_idx ON secrets(expires_at);

CREATE TABLE access_requests (
    id UUID PRIMARY KEY,
    secret_id UUID NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    requester_id UUID NOT NULL,
    requester_email TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','denied','revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at TIMESTAMPTZ,
    UNIQUE(secret_id, requester_id)
);
CREATE INDEX access_requests_requester_idx ON access_requests(requester_id, status);

CREATE TABLE secret_views (
    id BIGSERIAL PRIMARY KEY,
    secret_id UUID NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    user_email TEXT NOT NULL,
    ip TEXT NOT NULL,
    viewed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX secret_views_secret_idx ON secret_views(secret_id, viewed_at);

-- Events survive secret deletion and are committed atomically with business data.
CREATE TABLE outbox (
    event_id UUID PRIMARY KEY,
    type TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX outbox_created_idx ON outbox(created_at, event_id);
