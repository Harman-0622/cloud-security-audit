import json
import os
from web3 import Web3

# Paths
BUILD_PATH = os.path.join(os.path.dirname(__file__), 'contract_data.json')

def deploy_contract():
    # 1. Connect to Ganache GUI
    w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545"))
    if not w3.is_connected():
        print("❌ Could not connect to Ganache. Ensure Ganache GUI is open and running on port 7545!")
        return

    deployer_account = w3.eth.accounts[0]
    print(f"🔗 Connected! Deploying from account: {deployer_account}")

    # 2. Load our manually compiled ABI and Bytecode
    with open(BUILD_PATH, 'r') as f:
        contract_data = json.load(f)

    abi = contract_data['abi']
    bytecode = contract_data['bytecode']

    # 3. Deploy to Ganache
    print("🚀 Deploying to Ganache EVM...")
    AuditLedger = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = AuditLedger.constructor().transact({'from': deployer_account})
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    # 4. Save the deployed address back to our JSON file
    contract_data["address"] = tx_receipt.contractAddress
    contract_data["deployer"] = deployer_account
    
    with open(BUILD_PATH, 'w') as f:
        json.dump(contract_data, f, indent=4)

    print(f"✅ Contract deployed successfully at address: {tx_receipt.contractAddress}")

if __name__ == "__main__":
    deploy_contract()