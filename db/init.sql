CREATE TABLE IF NOT EXISTS sensor_readings (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    device_id VARCHAR(64) NOT NULL,
    zone VARCHAR(64) NOT NULL DEFAULT 'rack1',
    temperature DOUBLE,
    humidity DOUBLE,
    noise_db DOUBLE,
    INDEX idx_sensor_time (time),
    INDEX idx_sensor_device_time (device_id, time)
);

CREATE TABLE IF NOT EXISTS ai_anomalies (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    device_id VARCHAR(64) NOT NULL,
    anomaly_score DOUBLE,
    is_anomaly BOOLEAN NOT NULL DEFAULT FALSE,
    predicted_critical_min DOUBLE,
    message TEXT,
    INDEX idx_ai_time (time)
);

CREATE TABLE IF NOT EXISTS access_cards (
    id INT AUTO_INCREMENT PRIMARY KEY,
    credential_hash VARCHAR(128) UNIQUE NOT NULL,
    owner_name VARCHAR(100) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'staff',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS access_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    device_id VARCHAR(64) NOT NULL,
    credential_hash VARCHAR(128),
    owner_name VARCHAR(100),
    granted BOOLEAN NOT NULL,
    reason VARCHAR(255),
    INDEX idx_access_time (time)
);

CREATE TABLE IF NOT EXISTS device_status (
    device_id VARCHAR(64) PRIMARY KEY,
    status VARCHAR(20) NOT NULL DEFAULT 'offline',
    last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    meta JSON
);

CREATE TABLE IF NOT EXISTS system_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source VARCHAR(64) NOT NULL,
    level VARCHAR(20) NOT NULL DEFAULT 'INFO',
    message TEXT NOT NULL,
    details JSON,
    INDEX idx_syslogs_time (time)
);

CREATE TABLE IF NOT EXISTS command_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    device_id VARCHAR(64) NOT NULL,
    issued_by VARCHAR(100) NOT NULL,
    command VARCHAR(100) NOT NULL,
    payload JSON,
    INDEX idx_cmd_time (time)
);
