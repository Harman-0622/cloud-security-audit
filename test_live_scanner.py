from core.scanner.azure_live_scanner import scan_live_storage, scan_live_nsgs

print("Scanning Live Azure Storage Accounts...")
storage_findings = scan_live_storage(resource_group="rg-cspm-demo")
for f in storage_findings:
    print(f"[{f['status']}] {f['resource_name']} - {f['cis_rule_id']} ({f['nist_function']})")

print("\nScanning Live Azure Network Security Groups...")
nsg_findings = scan_live_nsgs(resource_group="rg-cspm-demo")
for f in nsg_findings:
    print(f"[{f['status']}] {f['resource_name']} - {f['cis_rule_id']} ({f['nist_function']})")