import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), 'audit_store.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans (
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
                )''')

    c.execute('''CREATE TABLE IF NOT EXISTS findings (
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
                )''')

    c.execute('''CREATE TABLE IF NOT EXISTS blockchain_logs (
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
                )''')
    conn.commit()
    conn.close()

def save_scan(scan_id, scores, tx_hash, report_hash, findings, tx_meta=None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    c.execute('''INSERT OR REPLACE INTO scans 
                 (scan_id, timestamp, global_score, identify_score, protect_score, detect_score,
                  total_rules, passed_rules, failed_rules, report_hash, raw_json_path)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
              (scan_id, timestamp, scores.get('global_score', 0),
               scores.get('identify_score', 0), scores.get('protect_score', 0), scores.get('detect_score', 0),
               scores.get('total_rules', len(findings)), scores.get('passed_rules', 0), scores.get('failed_rules', 0),
               report_hash, f"/static/reports/{scan_id}.pdf"))

    for f in findings:
        c.execute('''INSERT INTO findings 
                     (scan_id, resource_type, resource_name, cis_rule_id, nist_function, severity, weight, status, remediation)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (scan_id, f.get('resource_type', 'General'), f.get('resource_name', 'N/A'),
                   f.get('cis_rule_id', 'N/A'), f.get('nist_function', 'PROTECT'),
                   f.get('severity', 'LOW'), f.get('weight', 1), f.get('status', 'FAIL'),
                   f.get('remediation', '')))

    meta = tx_meta or {}
    c.execute('''INSERT OR REPLACE INTO blockchain_logs
                 (scan_id, report_hash, tx_hash, block_number, gas_used, issuer_address, contract_address, committed_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
              (scan_id, report_hash, tx_hash,
               meta.get('block_number', 104),
               meta.get('gas_used', 4712388),
               meta.get('issuer_address', '0x21f19a14950afae95934f95d78fabf194db5e5ad'),
               meta.get('contract_address', '0x8B757aD9A22d8C7B07e05C3Bf3B73738B1e'),
               timestamp))

    conn.commit()
    conn.close()

def get_all_scans():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    # Dynamically detects whether a scan belongs to AWS or Azure by inspecting its rules and resource types
    c.execute('''SELECT s.*, b.tx_hash,
                        CASE 
                            WHEN s.scan_id LIKE '%AWS%' THEN 'aws'
                            WHEN EXISTS (
                                SELECT 1 FROM findings f 
                                WHERE f.scan_id = s.scan_id 
                                  AND (f.cis_rule_id LIKE 'CIS-AWS%' OR f.resource_type LIKE 'AWS%')
                            ) THEN 'aws'
                            ELSE 'azure'
                        END AS cloud_provider
                 FROM scans s 
                 LEFT JOIN blockchain_logs b ON s.scan_id = b.scan_id 
                 ORDER BY s.timestamp DESC''')
    rows = c.fetchall()
    conn.close()
    return [dict(ix) for ix in rows]

def get_all_findings():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM findings ORDER BY finding_id DESC LIMIT 100')
    rows = c.fetchall()
    conn.close()
    return [dict(ix) for ix in rows]

def get_all_blockchain_logs():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM blockchain_logs ORDER BY log_id DESC')
    rows = c.fetchall()
    conn.close()
    return [dict(ix) for ix in rows]

def get_scan_by_id(scan_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM scans WHERE scan_id = ?', (scan_id,))
    scan = c.fetchone()
    if not scan:
        conn.close()
        return None
    scan_dict = dict(scan)

    c.execute('SELECT * FROM findings WHERE scan_id = ?', (scan_id,))
    scan_dict['findings'] = [dict(ix) for ix in c.fetchall()]

    c.execute('SELECT * FROM blockchain_logs WHERE scan_id = ?', (scan_id,))
    b_log = c.fetchone()
    scan_dict['tx_hash'] = b_log['tx_hash'] if b_log else 'Pending'

    # Attach detected cloud provider
    is_aws = ('AWS' in scan_id) or any('CIS-AWS' in (f.get('cis_rule_id') or '') or 'AWS' in (f.get('resource_type') or '') for f in scan_dict['findings'])
    scan_dict['cloud_provider'] = 'aws' if is_aws else 'azure'

    conn.close()
    return scan_dict

   