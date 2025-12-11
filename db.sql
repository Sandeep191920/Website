CREATE TABLE users (
id SERIAL PRIMARY KEY,
username TEXT UNIQUE NOT NULL,
email TEXT UNIQUE NOT NULL,
password_hash TEXT NOT NULL,
created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);


CREATE TABLE login_otps (
id SERIAL PRIMARY KEY,
user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
otp TEXT NOT NULL,
expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
used BOOLEAN DEFAULT FALSE,
created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);


-- Optional index to purge expired otps quickly
CREATE INDEX idx_login_otps_expires_at ON login_otps(expires_at);