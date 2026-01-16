
import os
import sys
import psycopg2
import psycopg2.extras
from tabulate import tabulate
from dotenv import load_dotenv

# Charger les variables AVANT d'importer PostgresDB qui les lit
load_dotenv()

# Add parent dir to path to import core
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.PostgresDB import DataBase

def check_tables():
    print("\n=== VÉRIFICATION DES TABLES ===")
    
    # Connexion raw pour voir la vérité nue
    db = DataBase()
    params = db.get_connection_params()
    
    try:
        conn = psycopg2.connect(**params)
        cursor = conn.cursor()
        
        # Lister les tables
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
            ORDER BY table_name;
        """)
        tables = [row[0] for row in cursor.fetchall()]
        
        expected = [
            'snmp_v1', 'snmp_v2', 'snmp_v3', 
            'users', 'registration_tickets', 'trusted_devices', 'twofa_codes', 'sessions'
        ]
        
        print(f"Tables trouvées ({len(tables)}): {', '.join(tables)}")
        
        missing = [t for t in expected if t not in tables]
        if missing:
            print(f"❌ MANQUANTES : {', '.join(missing)}")
        else:
            print("✅ Toutes les tables attendues sont présentes.")
            
        return conn
    except Exception as e:
        print(f"❌ Erreur connexion: {e}")
        return None

def verify_encryption(conn):
    print("\n=== VÉRIFICATION DU CHIFFREMENT ===")
    
    # 1. Insérer une donnée via l'ORM (qui chiffrera)
    print("-> Insertion d'un paquet test SNMPv1...")
    db = DataBase()
    
    # Données claires
    test_data = {
        "mac_src": "00:11:22:33:44:55", # Chiffré
        "ip_src": "192.168.1.100",      # Chiffré
        "snmp_community": "secret_comm", # Chiffré
        "snmp_pdu_type": "GET",
        "port_src": 12345,
        "port_dst": 161
    }
    
    try:
        if not db.encryption_enabled:
            print("⚠️ ATTENTION : Chiffrement DÉSACTIVÉ dans PostgresDB (SNIFFER_KEY manquante ?)")
        else:
            print("🔒 Chiffrement ACTIVÉ dans l'application.")

        db.initDB() # S'assurer que ça existe
        db.wrData("snmp_v1", test_data)
        print("✅ Donnée insérée via PostgresDB.")
        
        # 2. Lire via Raw SQL (pour voir si c'est chiffré)
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute("SELECT * FROM snmp_v1 ORDER BY id DESC LIMIT 1")
        raw_row = cursor.fetchone()
        
        print("\n[VUE DIRECTE BDD (Raw SQL)]")
        headers = ["Colonne", "Valeur Stockée", "Est Chiffré ?"]
        table_data = []
        
        encrypted_cols = ["mac_src", "ip_src", "snmp_community"]
        
        for col in encrypted_cols:
            val = raw_row[col]
            # Détection naïve : Fernet commence souvent par gAAAA...
            is_encrypted = str(val).startswith("gAAAA") if val else False
            status = "✅ OUI" if is_encrypted else "❌ NON (Clair)"
            table_data.append([col, val[:30] + "..." if val and len(str(val)) > 30 else val, status])
            
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        
        # 3. Lire via App (pour voir si c'est déchiffré)
        print("\n[VUE APPLICATION (via getData)]")
        app_rows = db.getLatest("snmp_v1", list(test_data.keys()), limit=1)
        if app_rows:
            app_row = app_rows[0]
            # Mapper l'ordre des colonnes
            # getLatest retourne un tuple dans l'ordre demandé
            
            print(f"MAC (Déchiffré): {app_row[0]} (Attendu: {test_data['mac_src']})")
            print(f"IP  (Déchiffré): {app_row[1]} (Attendu: {test_data['ip_src']})")
            
            if app_row[0] == test_data['mac_src']:
                print("✅ Déchiffrement transparent fonctionnel.")
            else:
                print("❌ Erreur de déchiffrement.")
        
    except Exception as e:
        print(f"Erreur test chiffrement: {e}")

if __name__ == "__main__":
    conn = check_tables()
    if conn:
        verify_encryption(conn)
        conn.close()
