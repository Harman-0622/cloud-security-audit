import json
import os

MOCK_DATA_PATH = os.path.join(os.path.dirname(__file__), '../../mock_data/storage_accounts.json')

def scan_storage():
    with open(MOCK_DATA_PATH, 'r') as f:
        resources = json.load(f)
    
    findings = []
    for res in resources:
        # ----------------------------------------------------
        # 1. IDENTIFY Function: Resource Asset Tagging (CIS 1.21)
        # ----------------------------------------------------
        tags = res.get('tags', {})
        has_required_tags = bool(tags.get('Environment') and tags.get('Owner'))
        findings.append({
            "resource_type": "Storage",
            "resource_name": res["name"],
            "cis_rule_id": "CIS-1.21",
            "nist_function": "IDENTIFY",
            "severity": "LOW",
            "weight": 1,
            "status": "PASS" if has_required_tags else "FAIL",
            "remediation": "Apply mandatory resource tags (Environment, Owner) for asset inventory tracking."
        })

        # ----------------------------------------------------
        # 2. PROTECT Function: Blob Public Access (CIS 3.6)
        # ----------------------------------------------------
        blob_public = res.get('allowBlobPublicAccess', True)
        findings.append({
            "resource_type": "Storage",
            "resource_name": res["name"],
            "cis_rule_id": "CIS-3.6",
            "nist_function": "PROTECT",
            "severity": "HIGH",
            "weight": 3,
            "status": "FAIL" if blob_public else "PASS",
            "remediation": "Set allowBlobPublicAccess to false to prevent anonymous read access."
        })
        
        # ----------------------------------------------------
        # 3. PROTECT Function: Secure Transfer / HTTPS (CIS 3.1)
        # ----------------------------------------------------
        https_only = res.get('enableHttpsTrafficOnly', False)
        findings.append({
            "resource_type": "Storage",
            "resource_name": res["name"],
            "cis_rule_id": "CIS-3.1",
            "nist_function": "PROTECT",
            "severity": "MEDIUM",
            "weight": 2,
            "status": "PASS" if https_only else "FAIL",
            "remediation": "Enable Secure transfer required (HTTPS only) to mandate encrypted transit."
        })

        # ----------------------------------------------------
        # 4. PROTECT Function: Enforce TLS 1.2+ (CIS 3.7)
        # ----------------------------------------------------
        min_tls = res.get('minimumTlsVersion', 'TLS1_0')
        tls_valid = min_tls in ['TLS1_2', 'TLS1_3']
        findings.append({
            "resource_type": "Storage",
            "resource_name": res["name"],
            "cis_rule_id": "CIS-3.7",
            "nist_function": "PROTECT",
            "severity": "HIGH",
            "weight": 3,
            "status": "PASS" if tls_valid else "FAIL",
            "remediation": "Set Minimum TLS version to TLS 1.2 or higher."
        })

        # ----------------------------------------------------
        # 5. DETECT Function: Storage Analytics Logging (CIS 3.3)
        # ----------------------------------------------------
        logging_cfg = res.get('logging', {})
        logs_enabled = (
            logging_cfg.get('read', False) and 
            logging_cfg.get('write', False) and 
            logging_cfg.get('delete', False)
        )
        findings.append({
            "resource_type": "Storage",
            "resource_name": res["name"],
            "cis_rule_id": "CIS-3.3",
            "nist_function": "DETECT",
            "severity": "MEDIUM",
            "weight": 2,
            "status": "PASS" if logs_enabled else "FAIL",
            "remediation": "Enable Storage logging for read, write, and delete requests to capture audit trails."
        })
        
    return findings