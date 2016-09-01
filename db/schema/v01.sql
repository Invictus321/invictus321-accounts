CREATE TABLE account (
	id VARCHAR(255) PRIMARY KEY,
	salt BYTEA,
	password_hash BYTEA
);