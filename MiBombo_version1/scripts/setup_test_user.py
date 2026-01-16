
from dotenv import load_dotenv
load_dotenv()

from core.snmp_credentials import snmp_cred_mgr
import os


# Ensure clean slate maybe? No, just add/overwrite.
print("Adding test user 'admin'...")
try:
    snmp_cred_mgr.add_user(
        username="admin",
        auth_proto="SHA",
        auth_key="12345678",
        priv_proto="AES",
        priv_key="87654321"
    )
    print("User 'admin' added successfully to secure store.")
except Exception as e:
    print(f"Error: {e}")
