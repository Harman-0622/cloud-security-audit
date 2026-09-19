import json
import os

MOCK_DATA_PATH = os.path.join(os.path.dirname(__file__), '../../mock_data/network_security_groups.json')

def scan_nsgs():
    with open(MOCK_DATA_PATH, 'r') as f:
        resources = json.load(f)
    
    findings = []
    for res in resources:
        is_vulnerable = False
        
        # Loop through all security rules in the NSG
        for rule in res.get('securityRules', []):
            props = rule.get('properties', {})
            access = props.get('access')
            source = props.get('sourceAddressPrefix')
            port = props.get('destinationPortRange')
            
            # If a rule allows access from ANY source to Port 22 or 3389, it's a critical fail
            if access == 'Allow' and source in ['*', 'Internet', '0.0.0.0/0']:
                if port in ['22', '3389', '*']:
                    is_vulnerable = True
        
        findings.append({
            "resource_type": "NSG",
            "resource_name": res["name"],
            "cis_rule_id": "CIS-6.1",
            "nist_function": "PROTECT",
            "severity": "HIGH",
            "weight": 3,
            "status": "FAIL" if is_vulnerable else "PASS",
            "remediation": "Restrict SSH (22) and RDP (3389) access from the internet."
        })
        
    return findings