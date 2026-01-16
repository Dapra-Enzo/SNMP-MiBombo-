# 📖 README - MiBombo Suite

**Version**: 1.1.0  
**Date**: 2026-01-13

---

## 🎯 Démarrage Rapide

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

## 📁 Structure du Projet

```
MiBombo_Station_v18/
├── 📂 docs/              # Documentation
│   ├── security/         # Sécurité
│   └── pki/             # PKI
├── 📂 scripts/           # Scripts utilitaires
│   └── pki/             # Scripts PKI
├── 📂 pki/              # Certificats
├── 📂 core/             # Modules principaux
├── 📂 gui/              # Interface graphique
└── 🐍 main.py           # Point d'entrée
```

Voir [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) pour les détails.

---

## 🔐 Sécurité

### Checklist
📋 **[docs/security/TODO_SECURITY.md](docs/security/TODO_SECURITY.md)**
- 60 tâches de sécurité
- Organisées en 5 phases
- Priorisées par criticité

### État Actuel
✅ **5/8 vulnérabilités critiques corrigées**
- ✅ Secrets externalisés (`.env`)
- ✅ PKI régénérée
- ✅ Headers HTTP sécurisés
- ⏳ 3 restantes (SSL verification, password policy, tests)

---

## 🔑 PKI (Certificats)

### Guide Complet
📖 **[docs/pki/PKI_MANAGEMENT.md](docs/pki/PKI_MANAGEMENT.md)**

### Durées de Validité
- **Root CA**: 5 ans
- **Sub CA**: 1 an
- **Station**: 90 jours

### Commandes
```bash
# Générer PKI complète
./scripts/pki/generate_pki.sh

# Renouveler Station (tous les 80 jours)
./scripts/pki/renew_station_cert.sh
```

---

## 📈 Scalabilité

### Plan Complet
📊 **[docs/SCALABILITY_PLAN.md](docs/SCALABILITY_PLAN.md)**

### Objectif
- **Actuel**: 100 appareils
- **Cible**: 10 000 appareils

### Solutions Rapides (30 min)
1. Batch writes SQLite → 10x performance
2. Gunicorn workers → 100x API
3. Index DB → 10x requêtes

---

## 🛠️ Scripts Utilitaires

| Script | Description | Localisation |
|--------|-------------|--------------|
| `generate_pki.sh` | Génération PKI complète | `scripts/pki/` |
| `renew_station_cert.sh` | Renouvellement Station | `scripts/pki/` |
| `check_security_headers.sh` | Vérification headers HTTP | `scripts/` |

---

## 📦 Installation

### Prérequis
- Python 3.13+
- OpenSSL
- Root access (pour sniffing réseau)

### Dépendances
```bash
pip install -r requirements.txt
```

Versions pinnées pour sécurité et reproductibilité.

---

## 🚀 Utilisation

### Lancer l'Application
```bash
sudo ./venv/bin/python main.py
```

### API REST
- **URL**: `https://localhost:5000`
- **Docs**: `https://localhost:5000/api/docs`
- **Auth**: Bearer token (voir docs API)

### Interface GUI
- Login: `admin` / `admin` (à changer au premier login)
- Tabs: SOC, NOC, Synthèse, API

---

## 🔒 Configuration Sécurisée

### Fichier .env
```bash
# Copier le template
cp .env.example .env

# Générer des clés fortes
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# Éditer .env avec vos clés
nano .env
```

### Variables Importantes
- `FLASK_SECRET_KEY`: Clé Flask (32 bytes)
- `INFLUXDB_TOKEN`: Token InfluxDB
- `AUTH_KEY`: Clé chiffrement auth
- `SNIFFER_KEY`: Clé chiffrement sniffer

---

## 📝 Documentation

| Document | Description |
|----------|-------------|
| [TODO_SECURITY.md](docs/security/TODO_SECURITY.md) | Checklist sécurité (60 tâches) |
| [PKI_MANAGEMENT.md](docs/pki/PKI_MANAGEMENT.md) | Guide gestion PKI |
| [SCALABILITY_PLAN.md](docs/SCALABILITY_PLAN.md) | Plan de scalabilité |
| [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) | Structure du projet |

---

## 🧪 Tests

```bash
# Tests unitaires
pytest tests/

# Tests de sécurité
./scripts/check_security_headers.sh

# Scan vulnérabilités
pip install safety
safety check
```

---

## 🔄 Maintenance

### Renouvellement Certificats
```bash
# Station (tous les 80 jours)
./scripts/pki/renew_station_cert.sh

# Automatiser avec cron
0 2 */80 * * /path/to/renew_station_cert.sh && systemctl restart mibombo
```

### Backups
```bash
# Backup complet
tar -czf mibombo_backup_$(date +%Y%m%d).tar.gz \
  --exclude=venv --exclude=*.db --exclude=*.log .
```

---

## 📞 Support

### Problèmes Courants

**Certificat expiré**
```bash
./scripts/pki/renew_station_cert.sh
sudo systemctl restart mibombo
```

**Erreur SSL verification**
```bash
# Vérifier .env
grep FLASK_SECRET_KEY .env

# Régénérer PKI
./scripts/pki/generate_pki.sh
```

**Performance lente**
```bash
# Voir docs/SCALABILITY_PLAN.md
# Solutions rapides en 30 min
```

---

## 🎯 Roadmap

### Phase 1 - Sécurité (En cours)
- [x] Secrets externalisés
- [x] PKI sécurisée
- [x] Headers HTTP
- [ ] SSL verification
- [ ] Password policy
- [ ] Tests sécurité

### Phase 2 - Performance (Prochaine)
- [ ] Gunicorn workers
- [ ] Redis cache
- [ ] PostgreSQL migration

### Phase 3 - Scalabilité
- [ ] Load balancing
- [ ] Auto-scaling
- [ ] Multi-region

---

## 📄 Licence

MiBombo Suite - Propriétaire  
© 2026 MiBombo Corp

---

## 👥 Équipe

- DAPRA BOUDINA
- **Support**: security@mibombo.local

---

**Dernière mise à jour**: 2026-01-13  
**Version**: 1.1.0-secure
