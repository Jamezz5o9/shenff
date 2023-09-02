CREATE TABLE token
(
    id           SERIAL PRIMARY KEY,
    token        VARCHAR(255) NOT NULL,
    app_user_id  BIGINT       NOT NULL,
    created_date TIMESTAMP,
    updated_date TIMESTAMP,
    expiry_date  TIMESTAMP,
    token_type   VARCHAR(255) NOT NULL,
    FOREIGN KEY (app_user_id) REFERENCES app_user (id)
);
