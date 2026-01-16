from cryptography.fernet import Fernet
import os

keys = {
    "AUTH_KEY": "jXpZS3B9joCEGMGvm1Lr8oMIVJ9GiFqKcRh9qHV59Og",
    "SNIFFER_KEY": "Ne_6IwRvlfhpRB5QgxfmudoRuaoOj3DWtqGHYyLXSNw",
    "ENCRYPTION_KEY": "U2hNxUkas_BRg9aIPDGCVKww9rVt2qjbHA7YVanw_gk="
}

print(f"{'KEY NAME':<20} | {'LENGTH':<6} | {'VALID?'}")
print("-" * 40)

for name, k in keys.items():
    valid = "❌"
    try:
        Fernet(k)
        valid = "✅"
    except Exception as e:
        valid = f"❌ ({e})"
    print(f"{name:<20} | {len(k):<6} | {valid}")
