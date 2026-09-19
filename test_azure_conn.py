import os
from dotenv import load_dotenv
from azure.identity import ClientSecretCredential
from azure.mgmt.resource.resources import ResourceManagementClient

# Load variables from .env
load_dotenv()

tenant_id = os.getenv("AZURE_TENANT_ID")
client_id = os.getenv("AZURE_CLIENT_ID")
client_secret = os.getenv("AZURE_CLIENT_SECRET")
subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")

print("Authenticating with Azure...")

try:
    # 1. Establish credential handshake
    credential = ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret
    )

    # 2. Query Resource Groups via ResourceManagementClient
    resource_client = ResourceManagementClient(credential, subscription_id)
    print("Fetching active Resource Groups...")
    
    rg_list = list(resource_client.resource_groups.list())
    
    if rg_list:
        print("\nConnection Successful! Found Resource Groups:")
        for rg in rg_list:
            print(f" - {rg.name} (Location: {rg.location})")
    else:
        print("\nConnection Successful! (No resource groups found in this subscription yet).")

except Exception as e:
    print(f"\nAuthentication Failed: {e}")