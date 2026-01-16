# MiBombo Suite

**Version**: 1.1.0  
**Date**: 2026-01-16

---

## Description

MiBombo est une suite de monitoring réseau avec capture de paquets SNMP, détection d'anomalies et gestion des appareils. L'application propose une interface graphique moderne (CustomTkinter) et une API REST sécurisée.

---

## Démarrage Rapide

```bash
# 1. Générer la PKI
./scripts/pki/generate_pki.sh

# 2. Configurer les secrets
cp .env.example .env
# Éditer .env avec vos vraies clés

# 3. Installer les dépendances
pip install -r requirements.txt

# 4. Lancer l'application
sudo ./venv/bin/python main.py
```

---

## Structure du Projet

```
MiBombo_version1/
├── api/                 # API REST Flask
├── core/                # Modules principaux (analyse, auth, DB)
├── gui/                 # Interface graphique CustomTkinter
├── scripts/             # Scripts utilitaires
│   └── pki/             # Scripts PKI
├── pki/                 # Certificats SSL/TLS
├── data/                # Données (logs, devices, historique)
├── assets/              # Ressources (images, icônes)
├── main.py              # Point d'entrée
├── requirements.txt     # Dépendances Python
├── Dockerfile           # Build Docker
└── docker-compose.yml   # Orchestration Docker
```

---

## Prérequis

- Python 3.13+
- OpenSSL
- Accès root (pour sniffing réseau)
- PostgreSQL (optionnel, SQLite par défaut)

---

## Installation

### Installation Locale

```bash
# Créer un environnement virtuel
python3 -m venv venv
source venv/bin/activate

# Installer les dépendances
pip install -r requirements.txt

# Lancer
sudo ./run.sh
```

### Installation Docker

```bash
docker-compose up -d
```

---

## Utilisation

### Interface Graphique

```bash
sudo ./run.sh
```

- **Login par défaut**: `admin` / `admin`
- **Onglets**: Dashboard, Capture, Appareils, Topologie, Comportement, API

### API REST

- **URL**: `https://localhost:5000`
- **Documentation**: `https://localhost:5000/api/docs`
- **Authentification**: Bearer token

---

## Configuration

### Fichier .env

```bash
# Copier le template
cp .env.example .env

# Générer une clé secrète
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

### Variables d'Environnement

| Variable | Description |
|----------|-------------|
| `FLASK_SECRET_KEY` | Clé secrète Flask |
| `DATABASE_URL` | URL de connexion DB |
| `AUTH_KEY` | Clé de chiffrement auth |
| `SNIFFER_KEY` | Clé de chiffrement sniffer |

---

## PKI (Certificats)

### Durées de Validité

| Certificat | Durée |
|------------|-------|
| Root CA | 5 ans |
| Sub CA | 1 an |
| Station | 90 jours |

### Commandes

```bash
# Générer PKI complète
./scripts/pki/generate_pki.sh

# Renouveler certificat Station
./scripts/pki/renew_station_cert.sh
```

---

## Tests

```bash
# Tests unitaires
pytest tests/

# Vérification headers de sécurité
./scripts/check_security_headers.sh
```

---

## Maintenance

### Renouvellement Certificats

```bash
# Renouveler tous les 80 jours
./scripts/pki/renew_station_cert.sh

# Automatiser avec cron
0 2 */80 * * /path/to/renew_station_cert.sh && systemctl restart mibombo
```

### Backups

```bash
tar -czf mibombo_backup_$(date +%Y%m%d).tar.gz \
  --exclude=venv --exclude=*.db --exclude=*.log .
```

---

## Dépannage

| Problème | Solution |
|----------|----------|
| Certificat expiré | `./scripts/pki/renew_station_cert.sh` |
| Erreur SSL | Vérifier `.env` et régénérer PKI |
| Performance lente | Activer Gunicorn workers, ajouter index DB |

---

## 📚 Documentation

La documentation technique complète est disponible dans le dossier `docs/` :

- Guide de déploiement
- Architecture technique
- Guide de sécurité
- Manuel utilisateur

---

## Licence

MiBombo Suite - Propriétaire  
© 2026 - SAE 501/502 ENSA

---

## Équipe

- DAPRA BOUDINA
- IUT Béziers - Département R&T

---

**Dernière mise à jour**: 2026-01-16  
**Version**: 1.1.0
