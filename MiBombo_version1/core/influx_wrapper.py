import os
import time
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

class InfluxWrapper:
    """Wrapper pour l'écriture et la lecture de métriques dans InfluxDB."""
    
    _instance = None
    
    def __init__(self):
        self.url = os.environ.get("INFLUXDB_URL", "http://localhost:8086")
        self.token = os.environ.get("INFLUXDB_TOKEN", "my-super-secret-auth-token")
        self.org = os.environ.get("INFLUXDB_ORG", "mibombo-org")
        self.bucket = os.environ.get("INFLUXDB_BUCKET", "mibombo-bucket")
        self.client = None
        self.write_api = None
        self.query_api = None
        self._connected = False
        
        self.connect()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def connect(self):
        """Etablit la connexion avec InfluxDB."""
        try:
            self.client = InfluxDBClient(url=self.url, token=self.token, org=self.org)
            self.write_api = self.client.write_api(write_options=SYNCHRONOUS)
            self.query_api = self.client.query_api()
            
            # Simple check
            health = self.client.health()
            if health.status == "pass":
                self._connected = True
                print(f"[+] Connecté à InfluxDB: {self.url}")
            else:
                print(f"[!] InfluxDB Health warning: {health.message}")
                
        except Exception as e:
            print(f"[!] Erreur connexion InfluxDB: {e}")
            self._connected = False

    def write_packet_stat(self, packet_size, protocol, src_ip):
        """Enregistre une métrique de paquet."""
        if not self._connected:
            return

        try:
            point = Point("network_traffic") \
                .tag("protocol", protocol) \
                .tag("src_ip", src_ip) \
                .field("size", int(packet_size)) \
                .time(time.time_ns(), WritePrecision.NS)
            
            self.write_api.write(bucket=self.bucket, org=self.org, record=point)
        except Exception as e:
            print(f"[!] Erreur écriture InfluxDB: {e}")

    def write_threat(self, level, ip):
        """Enregistre un niveau de menace."""
        if not self._connected:
            return

        try:
            point = Point("threat_level") \
                .tag("ip", ip) \
                .field("level", float(level)) \
                .time(time.time_ns(), WritePrecision.NS)
            
            self.write_api.write(bucket=self.bucket, org=self.org, record=point)
        except Exception as e:
            print(f"[!] Erreur écriture menace InfluxDB: {e}")

    def get_stats_last_hour(self):
        """Récupère les stats via Flux."""
        if not self._connected:
            return {}

        query = f"""
        from(bucket: "{self.bucket}")
          |> range(start: -1h)
          |> filter(fn: (r) => r["_measurement"] == "network_traffic")
          |> filter(fn: (r) => r["_field"] == "size")
          |> count()
        """
        # Note: Ceci est un exemple simplifié
        return {"msg": "Queries not yet fully implemented"}
