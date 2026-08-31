-- V2__seed_demo_oauth_client.sql

ALTER TABLE oauth_clients ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT true;

INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, enabled)
VALUES (
    'passly-demo-client',
    '$2b$10$Ty6yugLPTPCgm/lrVC.rauhZsLF7mPZ5T3oPWzQwXFHzobRa7xcmC',
    'Passly Demo Client (local development)',
    true
);

INSERT INTO oauth_client_redirect_uris (client_id, redirect_uri)
VALUES ('passly-demo-client', 'http://localhost:8080/login/oauth2/code/passly-demo');

INSERT INTO oauth_client_scopes (client_id, scope)
VALUES
    ('passly-demo-client', 'openid'),
    ('passly-demo-client', 'profile'),
    ('passly-demo-client', 'email');
