import os
import uuid

from flask import Flask, render_template, jsonify, request
from web3 import Web3

from core.reporting.pdf_generator import generate_pdf_report
from flask import send_from_directory
from flask import send_file
from core.scanner.storage_scanner import scan_storage
from core.scanner.nsg_scanner import scan_nsgs
from core.crypto.hasher import generate_report_hash
from core.rules.scoring_engine import calculate_scores
from core.web3_bridge.contract_interface import (
    record_audit_on_chain,
    verify_audit_on_chain,
    get_contract_address
)
from database.db_manager import (
    init_db,
    save_scan,
    get_all_scans,
    get_all_findings,
    get_all_blockchain_logs,
    get_scan_by_id
)
from core.scanner.azure_live_scanner import (
    scan_live_storage,
    scan_live_nsgs,
    get_azure_credentials
)
try:
    from azure.mgmt.resource import ResourceManagementClient
except ImportError:
    from azure.mgmt.resource.resources import ResourceManagementClient

from azure.identity import ClientSecretCredential
from core.scanner.aws_live_scanner import (
    scan_live_s3,
    scan_live_security_groups,
    get_aws_regions
)
import sqlite3
from database.db_manager import DB_PATH

app = Flask(__name__)
init_db()

# --- Server Lifecycle Tracking ---
# Generates a new unique session ID each time python app.py is started
SERVER_BOOT_ID = str(uuid.uuid4())

@app.context_processor
def inject_server_boot_lifecycle():
    return dict(server_boot_id=SERVER_BOOT_ID)

@app.after_request
def add_no_cache_headers(response):
    # Prevents aggressive browser bfcache on dynamic HTML templates
    if response.content_type.startswith("text/html"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

@app.route('/api/aws/regions', methods=['GET'])
def get_aws_scopes():
    """Returns AWS Regions for scope targeting."""
    try:
        regions = get_aws_regions()
        return jsonify({
            "status": "success",
            "regions": regions
        })
    except Exception as e:
        return jsonify({
            "status": "fallback",
            "regions": [
                {"name": "us-east-1", "location": "N. Virginia"},
                {"name": "us-west-2", "location": "Oregon"},
                {"name": "ap-south-1", "location": "Mumbai"}
            ]
        })

@app.route('/api/azure/resource_groups', methods=['GET'])
def get_azure_resource_groups():
    """Dynamically queries Azure ARM API for all Resource Groups in the subscription."""
    try:
        tenant_id = os.getenv("AZURE_TENANT_ID")
        client_id = os.getenv("AZURE_CLIENT_ID")
        client_secret = os.getenv("AZURE_CLIENT_SECRET")
        subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")

        if not all([tenant_id, client_id, client_secret, subscription_id]):
            return jsonify({
                "status": "fallback",
                "resource_groups": [
                    {"name": "rg-cspm-demo", "location": "centralindia"}
                ]
            })

        credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret
        )
        resource_client = ResourceManagementClient(credential, subscription_id)

        rg_list = []
        for rg in resource_client.resource_groups.list():
            # Handles both SDK object attributes and raw dictionary keys safely
            rg_name = getattr(rg, 'name', None) or (rg.get('name') if isinstance(rg, dict) else str(rg))
            rg_loc = getattr(rg, 'location', None) or (rg.get('location') if isinstance(rg, dict) else 'azure')
            
            # Prevent pushing "undefined" strings
            if rg_name and rg_name != "undefined":
                rg_list.append({"name": rg_name, "location": rg_loc})

        if not rg_list:
            rg_list = [{"name": "rg-cspm-demo", "location": "centralindia"}]

        return jsonify({
            "status": "success",
            "resource_groups": rg_list
        })
    except Exception as e:
        print(f"Error listing resource groups: {e}")
        return jsonify({
            "status": "fallback",
            "resource_groups": [
                {"name": "rg-cspm-demo", "location": "centralindia"}
            ]
        })

@app.route('/api/tamper_scan/<scan_id>', methods=['POST'])
def tamper_scan(scan_id):
    """Simulates an attacker modifying local database audit records."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Modify the score or spoof the stored report hash locally
    c.execute("UPDATE scans SET global_score = 99.9, report_hash = 'TAMPERED_HASH_0xDEADBEEF999999' WHERE scan_id = ?", (scan_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "tampered", "message": f"Scan {scan_id} database record altered!"})

# This route serves your existing HTML dashboard
@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/run_scan', methods=['POST'])
def run_scan():
    try:
        body = request.get_json(silent=True) or {}
        cloud_provider = body.get('cloud_provider', 'azure').lower()
        scan_mode = body.get('scan_mode', 'live')
        selected_scope = body.get('resource_group', None)
        
        # Clean invalid values
        if not selected_scope or selected_scope in ["ALL", "undefined", ""]:
            selected_scope = None

        wants_pdf = body.get('generate_pdf', True)
        commit_to_evm = body.get('commit_to_evm', True)
        compliance_threshold = int(body.get('compliance_threshold', 70))

        all_findings = []

        # 1. Execute Scanner based on Provider
        if cloud_provider == 'aws':
            s3_findings = scan_live_s3()
            sg_findings = scan_live_security_groups()
            all_findings = (s3_findings or []) + (sg_findings or [])
            meta_scope_label = selected_scope or "Global / Multi-Region"
            cloud_meta = {
                "provider": "Amazon Web Services (AWS)",
                "subscription_id": os.getenv("AWS_ACCESS_KEY_ID", "AKIA...DEMO")[:8] + "...",
                "resource_group": f"Region Scope: {meta_scope_label}"
            }
        else:
            # Default to Azure
            all_findings = []
            if scan_mode == 'live':
                try:
                    storage_findings = scan_live_storage(resource_group=selected_scope)
                    nsg_findings = scan_live_nsgs(resource_group=selected_scope)
                    all_findings = (storage_findings or []) + (nsg_findings or [])
                except Exception as azure_err:
                    print(f"[CSPM Warning] Live Azure scan error: {azure_err}. Falling back to rule simulator.")
                    all_findings = []

            # If live returned empty or threw an error, fall back to offline rules
            if not all_findings:
                storage_findings = scan_storage()
                nsg_findings = scan_nsgs()
                all_findings = (storage_findings or []) + (nsg_findings or [])

            cloud_meta = {
                "provider": "Microsoft Azure",
                "subscription_id": os.getenv("AZURE_SUBSCRIPTION_ID", "N/A"),
                "resource_group": selected_scope or "Entire Subscription (All Groups)"
            }

        # 2. Evaluate Scores
        scores = calculate_scores(all_findings)
        scores['compliance_threshold'] = compliance_threshold

        # 3. Generate Cryptographic Hashes
        provider_prefix = "AWS" if cloud_provider == 'aws' else "AZURE"
        scan_id = f"SCAN-{provider_prefix}-{uuid.uuid4().hex[:6].upper()}"
        report_hash = generate_report_hash(all_findings)

        # 4. EVM Ledger Execution
        tx_hash = "OFF_CHAIN_AUDIT"
        if commit_to_evm:
            try:
                tx_hash, chain_err = record_audit_on_chain(scan_id, report_hash)
                if not tx_hash:
                    tx_hash = "CHAIN_OFFLINE"
            except Exception as e:
                tx_hash = "CHAIN_ERROR"

        # 5. Persist to SQLite Database
        try:
            save_scan(
                scan_id=scan_id,
                scores=scores,
                tx_hash=tx_hash,
                report_hash=report_hash,
                findings=all_findings
            )
        except Exception as e:
            print(f"DB Save Warning: {e}")

        # 6. Generate PDF Report
        report_url = None
        if wants_pdf:
            try:
                pdf_name = generate_pdf_report(
                    scan_id=scan_id,
                    scores=scores,
                    findings=all_findings,
                    tx_hash=tx_hash,
                    report_hash=report_hash,
                    azure_meta=cloud_meta,
                    threshold=compliance_threshold  # <--- PASS IT HERE
                )
                report_url = f"/download_report/{pdf_name}"
            except Exception as e:
                import traceback
                print("--- PDF Generation Error ---")
                traceback.print_exc()

        return jsonify({
            "status": "success",
            "cloud_provider": cloud_provider,
            "scan_id": scan_id,
            "scores": scores,
            "report_hash": report_hash,
            "tx_hash": tx_hash,
            "commit_to_evm": commit_to_evm,
            "findings": all_findings,
            "report_url": report_url
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/download_report/<filename>')
def download_report(filename):
    reports_dir = os.path.join(os.path.dirname(__file__), 'static', 'reports')
    file_path = os.path.join(reports_dir, filename)

    # If the file does not exist, return a clean message rather than an unhandled 500 error
    if not os.path.exists(file_path):
        return (
            f"<h4>Report Not Ready</h4>"
            f"<p>Could not locate <code>{filename}</code> on the server. Please rerun the audit.</p>",
            404
        )

    # as_attachment=False tells modern browsers to render the PDF directly inside a new tab
    response = send_file(
        file_path,
        mimetype='application/pdf',
        as_attachment=False,
        download_name=filename
    )
    response.headers["Content-Disposition"] = f"inline; filename={filename}"
    return response

@app.route('/api/verify/<scan_id>', methods=['GET'])
def verify_scan(scan_id):
    # 1. Fetch on-chain record from Ganache smart contract
    chain_data, error = verify_audit_on_chain(scan_id)
    if error:
        return jsonify({"status": "error", "message": error}), 404

    # 2. Fetch local audit record from SQLite database
    record = get_scan_by_id(scan_id)
    if not record:
        return jsonify({"status": "error", "message": "Scan record not found in local database."}), 404

    # 3. Cryptographic integrity check
    local_hash = record.get('report_hash')
    onchain_hash = chain_data.get('report_hash')

    if local_hash != onchain_hash:
        return jsonify({
            "status": "tampered",
            "message": "INTEGRITY BREACH: Stored report hash does not match immutable EVM ledger record!",
            "local_hash": local_hash,
            "onchain_hash": onchain_hash
        }), 200

    return jsonify({
        "status": "success",
        "message": "Cryptographic integrity confirmed against EVM ledger.",
        "data": chain_data
    })

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan_record(scan_id):
    record = get_scan_by_id(scan_id)
    if not record:
        return jsonify({"status": "error", "message": "Scan not found"}), 404
    return jsonify({"status": "success", "data": record})


# --- NEW ROUTES FOR SIDEBAR TABS ---
@app.route('/integrations')
def integrations():
    # Read and mask credentials for secure display
    tenant_id = os.getenv("AZURE_TENANT_ID", "")
    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID", "")
    client_id = os.getenv("AZURE_CLIENT_ID", "")

    def mask_id(val):
        if not val or len(val) < 8:
            return "Not Configured"
        return f"{val[:4]}...{val[-4:]}"

    azure_connected = bool(tenant_id and subscription_id and client_id)

    # Check Ganache node status
    w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545"))
    ganache_online = False
    try:
        ganache_online = w3.is_connected()
    except Exception:
        ganache_online = False

    telemetry = {
        "azure_connected": azure_connected,
        "subscription_id": mask_id(subscription_id),
        "tenant_id": mask_id(tenant_id),
        "client_id": mask_id(client_id),
        "ganache_online": ganache_online,
        "contract_address": get_contract_address()
    }

    return render_template('integrations.html', telemetry=telemetry)

# Update the history view route:
@app.route('/history')
def history():
    past_scans = get_all_scans()
    all_findings = get_all_findings()
    blockchain_logs = get_all_blockchain_logs()
    return render_template('history.html', 
                           scans=past_scans, 
                           findings=all_findings, 
                           logs=blockchain_logs)

@app.route('/settings')
def settings():
    addr = get_contract_address()

    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID", "")
    tenant_id = os.getenv("AZURE_TENANT_ID", "")
    client_id = os.getenv("AZURE_CLIENT_ID", "")

    def mask_val(val):
        if not val or len(val) < 8:
            return "Not Configured"
        return f"{val[:6]}...{val[-4:]}"

    azure_info = {
        "subscription_id": mask_val(subscription_id),
        "tenant_id": mask_val(tenant_id),
        "client_id": mask_val(client_id)
    }

    return render_template('settings.html', contract_address=addr, azure_info=azure_info, server_boot_id=SERVER_BOOT_ID)

# --- REAL-TIME SYSTEM STATUS API ---
@app.route('/api/system_status', methods=['GET'])
def system_status():
    w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545"))
    return jsonify({
        "ganache_connected": w3.is_connected(),
        "server_boot_id": SERVER_BOOT_ID  # <--- Ensure this is returned        
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)