
CREATE DATABASE wisemapping;
CREATE USER wisemapping WITH PASSWORD 'password';
GRANT ALL PRIVILEGES ON DATABASE wisemapping TO wisemapping;

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO wisemapping;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO wisemapping;
