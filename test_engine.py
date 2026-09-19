from core.scanner.storage_scanner import scan_storage
from core.scanner.nsg_scanner import scan_nsgs
from core.crypto.hasher import generate_report_hash
from core.rules.scoring_engine import calculate_scores
from core.web3_bridge.contract_interface import record_audit_on_chain
import uuid
import json

print("\n🚀 STARTING CLOUD SECURITY AUDIT PIPELINE...\n")

# 1. Run Scanners
print("☁️  Step 1: Scanning Azure Configurations...")
all_findings = scan_storage() + scan_nsgs()

# 2. Calculate Scores
print("🧮 Step 2: Calculating NIST Compliance Scores...")
scores = calculate_scores(all_findings)

# 3. Generate Report Payload & Hash
print("🔐 Step 3: Generating SHA-256 Hash Digest...")
scan_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"
report_payload = {
    "scan_id": scan_id,
    "scores": scores,
    "findings": all_findings
}
report_hash = generate_report_hash(report_payload)
print(f"   -> Digest: {report_hash}")

# 4. Commit to Blockchain
print("⛓️  Step 4: Committing to Ganache Blockchain...")
tx_hash, error = record_audit_on_chain(scan_id, report_hash)

if error:
    print(f"\n❌ BLOCKCHAIN ERROR: {error}")
else:
    print(f"   -> Transaction Hash: {tx_hash}")
    print("\n✅ PIPELINE EXECUTED SUCCESSFULLY! Priority 1 is Complete!")