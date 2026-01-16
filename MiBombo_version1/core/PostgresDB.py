"""
PostgresDB.py - Gestion de la base de données PostgreSQL pour MiBombo (Architecture SI)
Remplace SQLiteDB pour les déploiements en production.
"""

import psycopg2
import psycopg2.extras
import os
import json
from datetime import datetime

# Chiffrement optionnel
try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    Fernet = None


class DataBase(object):
    """
    Gestionnaire de base de données PostgreSQL.
    Respecte l'interface de core/SQLiteDB.Database pour compatibilité directe.
    
    Configuration requise via variables d'environnement (.env):
    - PG_HOST
    - PG_PORT (def: 5432)
    - PG_DB
    - PG_USER
    - PG_PASSWORD
    - SNIFFER_KEY (pour le chiffrement)
    """
    
    # Colonnes contenant des données sensibles à chiffrer
    ENCRYPTED_COLUMNS = [
        "snmp_community", "snmp_oidsValues", 
        "ip_src", "ip_dst", 
        "mac_src", "mac_dst",
        "snmp_usm_user_name"
    ]
    
    def __init__(self, dbFile: str = None, require_encryption: bool = False):
        """
        Initialise le connecteur PostgreSQL.
        L'argument dbFile est ignoré (compatibilité legacy) mais conservé dans la signature.
        """
        self.connection = None
        self.cursor = None
        self.cipher = None
        self.encryption_enabled = False
        
        # Init chiffrement
        self._init_encryption(require_encryption)
        
    def _init_encryption(self, require: bool = False):
        """Initialise le moteur de chiffrement Fernet."""
        key_str = os.getenv("SNIFFER_KEY")
        
        if not key_str or not CRYPTO_AVAILABLE:
            if require:
                raise ValueError("SNIFFER_KEY manquante ou cryptography non installé")
            self.encryption_enabled = False
            return
            
        try:
            self.cipher = Fernet(key_str.encode())
            self.encryption_enabled = True
        except Exception as e:
            if require: raise e
            print(f"[PGSQL] Erreur chiffrement: {e}")
            self.encryption_enabled = False

    def get_connection_params(self):
        """Récupère les paramètres de connexion depuis l'environnement."""
        return {
            "host": os.getenv("PG_HOST", "localhost"),
            "port": os.getenv("PG_PORT", "5432"),
            "database": os.getenv("PG_DB", "mibombo_db"),
            "user": os.getenv("PG_USER", "postgres"),
            "password": os.getenv("PG_PASSWORD", "postgres")
        }

    def open(self):
        """Ouvre une connexion à PostgreSQL."""
        if self.connection is None or self.connection.closed:
            try:
                params = self.get_connection_params()
                self.connection = psycopg2.connect(**params)
                self.cursor = self.connection.cursor(cursor_factory=psycopg2.extras.DictCursor)
            except Exception as e:
                print(f"[PGSQL] Erreur de connexion: {e}")
                raise

    def close(self):
        """Ferme la connexion."""
        if self.connection and not self.connection.closed:
            self.connection.close()
            self.connection = None
            self.cursor = None

    def _encrypt(self, data):
        """Chiffre une donnée."""
        if data is None: return None
        
        # Conversion auto des structures complexes avant chiffrement
        if isinstance(data, (dict, list)):
            data = json.dumps(data)
            
        if not self.encryption_enabled or not self.cipher:
            return data
            
        try:
            return self.cipher.encrypt(str(data).encode()).decode()
        except:
            return data

    def _decrypt(self, data):
        """Déchiffre une donnée."""
        if data is None: return None
        if not self.encryption_enabled or not self.cipher:
            return data
            
        try:
            decrypted = self.cipher.decrypt(data.encode()).decode()
            # Tentative de parsing JSON auto si ça ressemble à du JSON
            if (decrypted.startswith("{") or decrypted.startswith("[")):
                try:
                    return json.loads(decrypted)
                except:
                    pass
            return decrypted
        except:
            return data

    def initDB(self):
        """Initialisation du schéma PostgreSQL (SI Style)."""
        self.open()
        try:
            # Table V1
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS snmp_v1 (
                    id SERIAL PRIMARY KEY,
                    time_stamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    mac_src TEXT, mac_dst TEXT,
                    ip_src TEXT, ip_dst TEXT,
                    port_src INTEGER, port_dst INTEGER,
                    snmp_community TEXT,
                    snmp_pdu_type VARCHAR(50),
                    
                    snmp_enterprise TEXT,
                    snmp_agent_addr INET,
                    snmp_generic_trap INTEGER,
                    snmp_specific_trap INTEGER,
                    
                    snmp_request_id BIGINT,
                    snmp_error_status INTEGER,
                    snmp_error_index INTEGER,
                    
                    snmp_oidsValues TEXT,
                    tag INTEGER
                );
                CREATE INDEX IF NOT EXISTS idx_v1_time ON snmp_v1(time_stamp);
                CREATE INDEX IF NOT EXISTS idx_v1_ip_src ON snmp_v1(ip_src);
            """)
            
            # Table V2
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS snmp_v2 (
                    id SERIAL PRIMARY KEY,
                    time_stamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    mac_src TEXT, mac_dst TEXT,
                    ip_src TEXT, ip_dst TEXT,
                    port_src INTEGER, port_dst INTEGER,
                    snmp_community TEXT,
                    snmp_pdu_type VARCHAR(50),
                    
                    snmp_request_id BIGINT,
                    snmp_error_status INTEGER,
                    snmp_error_index INTEGER,
                    snmp_non_repeaters INTEGER,
                    snmp_max_repetitions INTEGER,
                    
                    snmp_oidsValues TEXT,
                    tag INTEGER
                );
                CREATE INDEX IF NOT EXISTS idx_v2_time ON snmp_v2(time_stamp);
                CREATE INDEX IF NOT EXISTS idx_v2_ip_src ON snmp_v2(ip_src);
            """)

            # Table V3
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS snmp_v3 (
                    id SERIAL PRIMARY KEY,
                    time_stamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    mac_src TEXT, mac_dst TEXT,
                    ip_src TEXT, ip_dst TEXT,
                    port_src INTEGER, port_dst INTEGER,
                    
                    snmp_msg_id BIGINT,
                    snmp_msg_max_size INTEGER,
                    snmp_msg_flags VARCHAR(10),
                    snmp_msg_security_model INTEGER,
                    
                    snmp_usm_engine_id TEXT,
                    snmp_usm_engine_boots INTEGER,
                    snmp_usm_engine_time INTEGER,
                    snmp_usm_user_name TEXT,
                    snmp_usm_auth_protocol VARCHAR(50),
                    snmp_usm_priv_protocol VARCHAR(50),
                    snmp_usm_auth_params TEXT,
                    snmp_usm_priv_params TEXT,
                    
                    snmp_context_engine_id TEXT,
                    snmp_context_name TEXT,
                    snmp_pdu_type VARCHAR(50),
                    snmp_request_id BIGINT,
                    snmp_error_status INTEGER,
                    snmp_error_index INTEGER,
                    snmp_non_repeaters INTEGER,
                    snmp_max_repetitions INTEGER,
                    
                    snmp_oidsValues TEXT,
                    tag INTEGER,
                    
                    security_level VARCHAR(20),
                    is_encrypted BOOLEAN DEFAULT FALSE,
                    is_authenticated BOOLEAN DEFAULT FALSE,
                    decryption_status VARCHAR(50)
                );
                CREATE INDEX IF NOT EXISTS idx_v3_time ON snmp_v3(time_stamp);
                CREATE INDEX IF NOT EXISTS idx_v3_ip_src ON snmp_v3(ip_src);
            """)

            # ================================================================
            # TABLES AUTHENTIFICATION (Security Module)
            # ================================================================

            # Table utilisateurs
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id UUID PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    password_salt VARCHAR(64) NOT NULL,
                    email VARCHAR(255),
                    full_name VARCHAR(100),
                    role VARCHAR(20) DEFAULT 'user',
                    permissions JSONB DEFAULT '[]',
                    status VARCHAR(20) DEFAULT 'active',
                    two_fa_enabled BOOLEAN DEFAULT FALSE,
                    two_fa_secret TEXT,
                    must_change_password BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    notes TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
            """)

            # Table tickets d'inscription
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS registration_tickets (
                    id UUID PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    email VARCHAR(255) NOT NULL,
                    password_hash TEXT NOT NULL,
                    status VARCHAR(20) DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    reviewed_at TIMESTAMP,
                    reviewed_by UUID,
                    rejection_reason TEXT
                );
            """)
            
            # Table appareils de confiance (pour 2FA)
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS trusted_devices (
                    id UUID PRIMARY KEY,
                    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    device_hash VARCHAR(64) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    last_used TIMESTAMP,
                    UNIQUE(user_id, device_hash)
                );
            """)
            
            # Table codes 2FA
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS twofa_codes (
                    id SERIAL PRIMARY KEY,
                    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    code VARCHAR(10) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    used BOOLEAN DEFAULT FALSE
                );
            """)
            
            # Table sessions
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    token VARCHAR(64) PRIMARY KEY,
                    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    ip_address INET,
                    user_agent TEXT
                );
            """)
            
            self.connection.commit()
        except Exception as e:
            print(f"[PGSQL] Erreur initDB: {e}")
            self.connection.rollback()
        finally:
            self.close()

    def wrData(self, table: str, data: dict):
        """Écrit des données avec support JSON/Text auto."""
        self.open()
        try:
            secure_data = data.copy()
            
            # Pré-traitement pour PostgreSQL
            for k, v in secure_data.items():
                # Conversion des listes/dicts en JSON string (pour colonnes TEXT)
                # Mais si c'est chiffré, _encrypt le fait déjà
                if k in self.ENCRYPTED_COLUMNS:
                    secure_data[k] = self._encrypt(v)
                elif isinstance(v, (dict, list)):
                    secure_data[k] = json.dumps(v)

            columns = list(secure_data.keys())
            placeholders = ["%s"] * len(columns)
            values = list(secure_data.values())
            
            # Construction requête
            cols_str = ", ".join(columns)
            vals_str = ", ".join(placeholders)
            sql = f"INSERT INTO {table} ({cols_str}) VALUES ({vals_str})"
            
            self.cursor.execute(sql, values)
            self.connection.commit()
            
        except Exception as e:
            print(f"[PGSQL] Erreur wrData {table}: {e}")
            self.connection.rollback()
        finally:
            self.close()

    def getData(self, table: str, columns: list, where: str = None, params: tuple = (), decrypt: bool = True):
        self.open()
        try:
            cols = ", ".join(columns)
            sql = f"SELECT {cols} FROM {table}"
            if where:
                # Conversion placeholder SQLite (?) -> Postgres (%s) au cas où
                where_pg = where.replace("?", "%s")
                sql += f" WHERE {where_pg}"
            
            self.cursor.execute(sql, params)
            rows = self.cursor.fetchall()
            
            # Conversion DictRow -> Tuple pour compatibilité legacy
            # Et déchiffrement
            processed_rows = []
            for row in rows:
                new_row = []
                for col in columns:
                    val = row[col]
                    if decrypt and col in self.ENCRYPTED_COLUMNS:
                        val = self._decrypt(val)
                    # Convertir INET en str si nécessaire (psycopg2 le fait souvent bien)
                    new_row.append(val)
                processed_rows.append(tuple(new_row))
                
            return processed_rows
        except Exception as e:
            print(f"[PGSQL] Erreur getData: {e}")
            return []
        finally:
            self.close()

    def getLatest(self, table: str, columns: list, limit: int = 100, decrypt: bool = True):
        self.open()
        try:
            cols = ", ".join(columns)
            sql = f"SELECT {cols} FROM {table} ORDER BY id DESC LIMIT %s"
            
            self.cursor.execute(sql, (limit,))
            rows = self.cursor.fetchall()
            
            processed_rows = []
            for row in rows:
                new_row = []
                for col in columns:
                    val = row[col]
                    if decrypt and col in self.ENCRYPTED_COLUMNS:
                        val = self._decrypt(val)
                    new_row.append(val)
                processed_rows.append(tuple(new_row))
            return processed_rows
        finally:
            self.close()

    def getCount(self, table: str, where: str = None, params: tuple = ()) -> int:
        self.open()
        try:
            sql = f"SELECT COUNT(*) FROM {table}"
            if where:
                where_pg = where.replace("?", "%s")
                sql += f" WHERE {where_pg}"
            
            self.cursor.execute(sql, params)
            return self.cursor.fetchone()[0]
        except:
            return 0
        finally:
            self.close()

    def deleteOld(self, table: str, days: int = 30):
        self.open()
        try:
            # Syntax Postgres interval
            sql = f"DELETE FROM {table} WHERE time_stamp < NOW() - INTERVAL '%s days'"
            self.cursor.execute(sql, (days,))
            count = self.cursor.rowcount
            self.connection.commit()
            return count
        finally:
            self.close()

    def table_exists(self, table_name: str) -> bool:
        """Vérifie si une table existe (Compatibilité Legacy)."""
        self.open()
        try:
            self.cursor.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name = %s
                );
            """, (table_name,))
            return self.cursor.fetchone()[0]
        except Exception as e:
            print(f"[PGSQL] Erreur table_exists: {e}")
            return False
        finally:
            self.close()

    def getChamps(self, table: str) -> list:
        """Récupère la liste des champs d'une table."""
        self.open()
        try:
            self.cursor.execute("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = %s 
                ORDER BY ordinal_position
            """, (table,))
            return [row[0] for row in self.cursor.fetchall()]
        except Exception as e:
            print(f"[PGSQL] Erreur getChamps: {e}")
            return []
        finally:
            self.close()

    def getStatistics(self) -> dict:
        """Retourne des statistiques simples."""
        # On ne check pas table_exists à chaque fois pour perf, on assume initDB fait
        return {
            "v1_count": self.getCount("snmp_v1"),
            "v2_count": self.getCount("snmp_v2"),
            "v3_count": self.getCount("snmp_v3"),
            "encryption_enabled": self.encryption_enabled,
            "backend": "PostgreSQL"
        }
