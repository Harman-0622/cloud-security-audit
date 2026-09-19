import os
from dotenv import load_dotenv
from azure.identity import ClientSecretCredential
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient

load_dotenv()

def get_azure_credentials():
    return ClientSecretCredential(
        tenant_id=os.getenv("AZURE_TENANT_ID"),
        client_id=os.getenv("AZURE_CLIENT_ID"),
        client_secret=os.getenv("AZURE_CLIENT_SECRET")
    ), os.getenv("AZURE_SUBSCRIPTION_ID")

def scan_live_storage(resource_group=None):
    credential, subscription_id = get_azure_credentials()
    storage_client = StorageManagementClient(credential, subscription_id)
    findings = []

    # Filter by resource group if supplied, otherwise scan full subscription
    accounts = (
        storage_client.storage_accounts.list_by_resource_group(resource_group)
        if resource_group
        else storage_client.storage_accounts.list()
    )

    for acct in accounts:
        # 1. CIS 1.21: Mandatory Asset Tagging (IDENTIFY)
        tags = acct.tags or {}
        has_tags = bool(tags.get('Environment') and tags.get('Owner'))
        findings.append({
            "resource_type": "Storage",
            "resource_name": acct.name,
            "cis_rule_id": "CIS-1.21",
            "nist_function": "IDENTIFY",
            "severity": "LOW",
            "weight": 1,
            "status": "PASS" if has_tags else "FAIL",
            "remediation": "Apply mandatory resource tags (Environment, Owner) for asset inventory tracking."
        })

        # 2. CIS 3.6: Public Blob Access (PROTECT)
        blob_public = getattr(acct, 'allow_blob_public_access', True)
        findings.append({
            "resource_type": "Storage",
            "resource_name": acct.name,
            "cis_rule_id": "CIS-3.6",
            "nist_function": "PROTECT",
            "severity": "HIGH",
            "weight": 3,
            "status": "FAIL" if blob_public else "PASS",
            "remediation": "Disable allowBlobPublicAccess to block anonymous unauthenticated read requests."
        })

        # 3. CIS 3.1: HTTPS Secure Transfer (PROTECT)
        https_only = getattr(acct, 'enable_https_traffic_only', False)
        findings.append({
            "resource_type": "Storage",
            "resource_name": acct.name,
            "cis_rule_id": "CIS-3.1",
            "nist_function": "PROTECT",
            "severity": "MEDIUM",
            "weight": 2,
            "status": "PASS" if https_only else "FAIL",
            "remediation": "Enable 'Secure transfer required' to enforce encrypted HTTPS transit."
        })

        # 4. CIS 3.7: Enforce TLS 1.2+ (PROTECT)
        min_tls = getattr(acct, 'minimum_tls_version', 'TLS1_0')
        tls_valid = min_tls in ['TLS1_2', 'TLS1_3']
        findings.append({
            "resource_type": "Storage",
            "resource_name": acct.name,
            "cis_rule_id": "CIS-3.7",
            "nist_function": "PROTECT",
            "severity": "HIGH",
            "weight": 3,
            "status": "PASS" if tls_valid else "FAIL",
            "remediation": "Configure minimum TLS version to TLS 1.2 or higher."
        })

    return findings

def scan_live_nsgs(resource_group=None):
    credential, subscription_id = get_azure_credentials()
    network_client = NetworkManagementClient(credential, subscription_id)
    findings = []

    nsgs = (
        network_client.network_security_groups.list(resource_group)
        if resource_group
        else network_client.network_security_groups.list_all()
    )

    for nsg in nsgs:
        rules = nsg.security_rules or []
        ssh_exposed = False
        rdp_exposed = False

        for r in rules:
            if r.access and r.access.lower() == 'allow' and r.direction and r.direction.lower() == 'inbound':
                prefix = r.source_address_prefix or ""
                prefixes = r.source_address_prefixes or []
                is_any = prefix in ['*', '0.0.0.0/0', 'Internet'] or ('*' in prefixes)

                if is_any:
                    ports = [str(r.destination_port_range)] if r.destination_port_range else [str(p) for p in (r.destination_port_ranges or [])]
                    if any(p in ['22', '*'] for p in ports):
                        ssh_exposed = True
                    if any(p in ['3389', '*'] for p in ports):
                        rdp_exposed = True

        findings.append({
            "resource_type": "Network Security Group",
            "resource_name": nsg.name,
            "cis_rule_id": "CIS-6.1",
            "nist_function": "PROTECT",
            "severity": "HIGH",
            "weight": 3,
            "status": "FAIL" if ssh_exposed else "PASS",
            "remediation": "Restrict inbound SSH (port 22) from wildcards (0.0.0.0/0 or Internet)."
        })

        findings.append({
            "resource_type": "Network Security Group",
            "resource_name": nsg.name,
            "cis_rule_id": "CIS-6.2",
            "nist_function": "PROTECT",
            "severity": "HIGH",
            "weight": 3,
            "status": "FAIL" if rdp_exposed else "PASS",
            "remediation": "Restrict inbound RDP (port 3389) from unrestricted sources."
        })

    return findings