CREATE TABLE task
(
    id            SERIAL PRIMARY KEY,
    task_id       VARCHAR(255),
    task_title    VARCHAR(255),
    task_body     TEXT,
    task_priority VARCHAR(50),
    completed     BOOLEAN,
    due_date      TIMESTAMP,
    app_user_id   BIGINT,
    task_status   VARCHAR(50),
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    modified_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at    TIMESTAMP
);
