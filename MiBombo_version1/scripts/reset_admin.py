
import os
import sys
import secrets
import hashlib
import binascii
from dotenv import load_dotenv

# Charger les variables (DB credentials)
load_dotenv()

# Add parent dir to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.PostgresDB import DataBase

def hash_password(password: str) -> str:
    """Hash PBKDF2 (copié de secure_auth pour éviter dépendances complexes)"""
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    )
    return f"pbkdf2:sha256:100000${salt}${binascii.hexlify(pwd_hash).decode('ascii')}"

def reset_admin():
    db = DataBase()
    db.open()
    
    new_pass = "admin"
    new_hash = hash_password(new_pass)
    
    # 1. Trouver l'admin
    sql_find = "SELECT id, username FROM users WHERE role = 'admin' LIMIT 1"
    db.cursor.execute(sql_find)
    row = db.cursor.fetchone()
    
    if not row:
        print("❌ Aucun administrateur trouvé !")
        return
        
    user_id = row['id']
    username = row['username']
    
    # 2. Update
    sql_update = """
        UPDATE users 
        SET password_hash = %s, must_change_password = TRUE 
        WHERE id = %s
    """
    db.cursor.execute(sql_update, (new_hash, user_id))
    db.connection.commit()
    
    print(f"✅ Mot de passe réinitialisé pour '{username}'.")
    print(f"🔑 Nouveau mot de passe : {new_pass}")
    print("ℹ️ Vous devrez le changer à la première connexion.")
    
    db.close()

if __name__ == "__main__":
    reset_admin()
