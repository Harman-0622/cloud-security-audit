CREATE TABLE IF NOT EXISTS scans (
    scan_id VARCHAR(64) PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    global_score REAL NOT NULL,
    identify_score REAL NOT NULL,
    protect_score REAL NOT NULL,
    detect_score REAL NOT NULL,
    total_rules INTEGER NOT NULL,
    passed_rules INTEGER NOT NULL,
    failed_rules INTEGER NOT NULL,
    report_hash VARCHAR(64) NOT NULL,
    raw_json_path TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id VARCHAR(64),
    resource_type VARCHAR(64) NOT NULL,
    resource_name VARCHAR(128) NOT NULL,
    cis_rule_id VARCHAR(32) NOT NULL,
    nist_function VARCHAR(32) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    weight INTEGER NOT NULL,
    status VARCHAR(16) NOT NULL,
    remediation TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);

CREATE TABLE IF NOT EXISTS blockchain_logs (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id VARCHAR(64),
    report_hash VARCHAR(64) NOT NULL,
    tx_hash VARCHAR(66) NOT NULL UNIQUE,
    block_number INTEGER NOT NULL,
    gas_used INTEGER NOT NULL,
    issuer_address VARCHAR(42) NOT NULL,
    contract_address VARCHAR(42) NOT NULL,
    committed_at DATETIME NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);