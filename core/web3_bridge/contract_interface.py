import json
import os
from web3 import Web3

BUILD_PATH = os.path.join(os.path.dirname(__file__), 'contract_data.json')

def record_audit_on_chain(scan_id, report_hash):
    """Sends the SHA-256 hash to the Ganache blockchain."""
    w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545"))
    if not w3.is_connected():
        return None, "❌ Ganache not connected. Is it running?"
        
    # Load the deployed contract address and ABI
    with open(BUILD_PATH, 'r') as f:
        data = json.load(f)
        
    contract = w3.eth.contract(address=data['address'], abi=data['abi'])
    deployer = data['deployer']
    
    try:
        # 1. Build and send the transaction
        tx_hash = contract.functions.recordAudit(scan_id, report_hash).transact({'from': deployer})
        
        # 2. Wait for it to be mined onto the blockchain
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        
        # Return the official transaction receipt hash
        return receipt.transactionHash.hex(), None
    except Exception as e:
        return None, str(e)


def verify_audit_on_chain(scan_id):
    """Reads the blockchain to verify an audit exists."""
    w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545"))
    if not w3.is_connected():
        return None, "Ganache not connected."
        
    with open(BUILD_PATH, 'r') as f:
        data = json.load(f)
        
    contract = w3.eth.contract(address=data['address'], abi=data['abi'])
    
    try:
        # Call the view function (does not cost gas)
        result = contract.functions.verifyAudit(scan_id).call()
        return {
            "report_hash": result[0],
            "timestamp": result[1],
            "issuer": result[2]
        }, None
    except Exception as e:
        return None, "Scan ID not found on the blockchain."

def get_contract_address():
    """Returns the deployed contract address from contract_data.json."""
    try:
        with open(BUILD_PATH, 'r') as f:
            data = json.load(f)
            return data.get('address', 'Unavailable')
    except Exception:
        return 'Unavailable'