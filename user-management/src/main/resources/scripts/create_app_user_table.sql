CREATE TABLE app_user
(
    id          SERIAL PRIMARY KEY,
    user_id     VARCHAR(255),
    email       VARCHAR(255) NOT NULL,
    password    VARCHAR(255) NOT NULL,
    name        VARCHAR(255),
    is_verified BOOLEAN      NOT NULL,
    image_url   VARCHAR(255),
    provider    VARCHAR(50),
    provider_id VARCHAR(255),
    role_id     BIGINT       NOT NULL,
    created_at  TIMESTAMP,
    modified_at TIMESTAMP,
    deleted_at  TIMESTAMP,
    FOREIGN KEY (role_id) REFERENCES role (id)
);
